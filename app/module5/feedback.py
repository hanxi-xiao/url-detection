"""SQLite persistence, deduplication, and review export for user feedback."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import PredictionContext, ReportWebsiteRequest, ReportWebsiteResult, TechnicalReason


class FeedbackError(Exception):
    pass


class AnalysisNotFoundError(FeedbackError):
    pass


class ReportURLMismatchError(FeedbackError):
    pass


class AnalysisConflictError(FeedbackError):
    pass


class FeedbackStorageError(FeedbackError):
    pass


class CaseResolutionError(FeedbackError):
    pass


class FeedbackRepository:
    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection, connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS analysis_records (
                    request_id TEXT PRIMARY KEY,
                    normalized_url TEXT NOT NULL,
                    normalized_url_hash TEXT NOT NULL,
                    model_version TEXT NOT NULL,
                    feature_schema_version TEXT NOT NULL,
                    phishing_probability REAL NOT NULL,
                    risk_score REAL NOT NULL,
                    risk_category TEXT NOT NULL,
                    features_json TEXT NOT NULL,
                    technical_reasons_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS feedback_cases (
                    case_id TEXT PRIMARY KEY,
                    normalized_url TEXT NOT NULL,
                    normalized_url_hash TEXT NOT NULL,
                    model_version TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    risk_category TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'NEW',
                    admin_decision TEXT,
                    admin_reason TEXT,
                    admin_screenshot_name TEXT,
                    admin_screenshot_data_url TEXT,
                    admin_decided_at TEXT,
                    admin_decided_by_email TEXT,
                    admin_decided_by_name TEXT,
                    report_count INTEGER NOT NULL CHECK (report_count >= 1),
                    first_reported_at TEXT NOT NULL,
                    last_reported_at TEXT NOT NULL,
                    UNIQUE (normalized_url_hash, model_version)
                );
                CREATE TABLE IF NOT EXISTS feedback_reports (
                    report_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    normalized_url_hash TEXT NOT NULL,
                    review_type TEXT NOT NULL DEFAULT 'report_suspicious',
                    employee_assessment TEXT NOT NULL DEFAULT 'Suspicious',
                    reason_code TEXT NOT NULL DEFAULT 'other',
                    comment TEXT,
                    reported_at TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES feedback_cases(case_id),
                    FOREIGN KEY (request_id) REFERENCES analysis_records(request_id),
                    UNIQUE (request_id, normalized_url_hash)
                );
                CREATE INDEX IF NOT EXISTS idx_feedback_cases_last_reported
                    ON feedback_cases(last_reported_at DESC);
                CREATE INDEX IF NOT EXISTS idx_feedback_reports_case
                    ON feedback_reports(case_id, reported_at DESC);
                CREATE TABLE IF NOT EXISTS policy_entries (
                    entry_id TEXT PRIMARY KEY,
                    normalized_url TEXT NOT NULL,
                    normalized_url_hash TEXT NOT NULL,
                    list_type TEXT NOT NULL CHECK (list_type IN ('allowlist', 'blocklist')),
                    decision_reason TEXT NOT NULL,
                    screenshot_name TEXT,
                    screenshot_data_url TEXT,
                    source_case_id TEXT,
                    decided_by_email TEXT NOT NULL,
                    decided_by_name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT,
                    UNIQUE (normalized_url_hash)
                );
                CREATE INDEX IF NOT EXISTS idx_policy_entries_hash
                    ON policy_entries(normalized_url_hash);
                """
            )
            existing_case_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(feedback_cases)").fetchall()
            }
            for column_name, definition in (
                ("admin_decision", "TEXT"),
                ("admin_reason", "TEXT"),
                ("admin_screenshot_name", "TEXT"),
                ("admin_screenshot_data_url", "TEXT"),
                ("admin_decided_at", "TEXT"),
                ("admin_decided_by_email", "TEXT"),
                ("admin_decided_by_name", "TEXT"),
            ):
                if column_name not in existing_case_columns:
                    connection.execute(
                        f"ALTER TABLE feedback_cases ADD COLUMN {column_name} {definition}"
                    )
            existing_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(feedback_reports)").fetchall()
            }
            if "review_type" not in existing_columns:
                connection.execute(
                    "ALTER TABLE feedback_reports ADD COLUMN review_type TEXT NOT NULL DEFAULT 'report_suspicious'"
                )
            if "employee_assessment" not in existing_columns:
                connection.execute(
                    "ALTER TABLE feedback_reports ADD COLUMN employee_assessment TEXT NOT NULL DEFAULT 'Suspicious'"
                )
            if "reason_code" not in existing_columns:
                connection.execute(
                    "ALTER TABLE feedback_reports ADD COLUMN reason_code TEXT NOT NULL DEFAULT 'other'"
                )
            existing_policy_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(policy_entries)").fetchall()
            }
            if "expires_at" not in existing_policy_columns:
                connection.execute("ALTER TABLE policy_entries ADD COLUMN expires_at TEXT")

    def save_analysis(self, context: PredictionContext, reasons: Iterable[TechnicalReason] = ()) -> None:
        url_hash = hash_normalized_url(context.normalized_url)
        reason_json = json.dumps([reason.to_dict() for reason in reasons], ensure_ascii=False, separators=(",", ":"))
        features_json = json.dumps(context.features, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        created_at = utc_now()
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    """
                    SELECT normalized_url, model_version, feature_schema_version, phishing_probability, risk_score, risk_category, features_json
                    FROM analysis_records
                    WHERE request_id = ?
                    """,
                    (context.request_id,),
                ).fetchone()
                if existing is not None:
                    same_analysis = (
                        existing["normalized_url"] == context.normalized_url
                        and existing["model_version"] == context.model_version
                        and existing["feature_schema_version"] == context.feature_schema_version
                        and float(existing["phishing_probability"]) == context.phishing_probability
                        and float(existing["risk_score"]) == context.risk_score
                        and existing["risk_category"] == context.risk_category.value
                        and existing["features_json"] == features_json
                    )
                    if not same_analysis:
                        raise AnalysisConflictError("requestId is already associated with different analysis data")
                    connection.execute(
                        """
                        UPDATE analysis_records
                        SET technical_reasons_json = ?
                        WHERE request_id = ?
                        """,
                        (reason_json, context.request_id),
                    )
                    return
                connection.execute(
                    """
                    INSERT INTO analysis_records (
                        request_id, normalized_url, normalized_url_hash, model_version, feature_schema_version,
                        phishing_probability, risk_score, risk_category, features_json, technical_reasons_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        context.request_id,
                        context.normalized_url,
                        url_hash,
                        context.model_version,
                        context.feature_schema_version,
                        context.phishing_probability,
                        context.risk_score,
                        context.risk_category.value,
                        features_json,
                        reason_json,
                        created_at,
                    ),
                )
        except FeedbackError:
            raise
        except sqlite3.Error as exc:
            raise FeedbackStorageError("failed to store analysis record") from exc

    def report_website(self, request: ReportWebsiteRequest) -> ReportWebsiteResult:
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                analysis = connection.execute("SELECT * FROM analysis_records WHERE request_id = ?", (request.request_id,)).fetchone()
                if analysis is None:
                    raise AnalysisNotFoundError(f"analysis {request.request_id!r} does not exist")
                if request.url != analysis["normalized_url"]:
                    raise ReportURLMismatchError("reported URL does not match the trusted analysis record")
                url_hash = str(analysis["normalized_url_hash"])
                previous_report = connection.execute(
                    """
                    SELECT reports.report_id, reports.case_id, reports.reported_at, cases.report_count
                    FROM feedback_reports AS reports
                    JOIN feedback_cases AS cases ON cases.case_id = reports.case_id
                    WHERE reports.request_id = ? AND reports.normalized_url_hash = ?
                    """,
                    (request.request_id, url_hash),
                ).fetchone()
                if previous_report is not None:
                    return ReportWebsiteResult(
                        report_id=str(previous_report["report_id"]),
                        case_id=str(previous_report["case_id"]),
                        duplicate=True,
                        report_count=int(previous_report["report_count"]),
                        reported_at=str(previous_report["reported_at"]),
                    )
                reported_at = utc_now()
                existing_case = connection.execute(
                    """
                    SELECT case_id, report_count
                    FROM feedback_cases
                    WHERE normalized_url_hash = ? AND model_version = ?
                    """,
                    (url_hash, analysis["model_version"]),
                ).fetchone()
                if existing_case is None:
                    case_id = new_identifier("case")
                    report_count = 1
                    duplicate = False
                    connection.execute(
                        """
                        INSERT INTO feedback_cases (
                            case_id, normalized_url, normalized_url_hash, model_version, risk_score,
                            risk_category, status, report_count, first_reported_at, last_reported_at
                        ) VALUES (?, ?, ?, ?, ?, ?, 'NEW', ?, ?, ?)
                        """,
                        (
                            case_id,
                            analysis["normalized_url"],
                            url_hash,
                            analysis["model_version"],
                            analysis["risk_score"],
                            analysis["risk_category"],
                            report_count,
                            reported_at,
                            reported_at,
                        ),
                    )
                else:
                    case_id = str(existing_case["case_id"])
                    report_count = int(existing_case["report_count"]) + 1
                    duplicate = True
                    connection.execute(
                        """
                        UPDATE feedback_cases
                        SET report_count = ?, last_reported_at = ?
                        WHERE case_id = ?
                        """,
                        (report_count, reported_at, case_id),
                    )
                report_id = new_identifier("report")
                connection.execute(
                    """
                    INSERT INTO feedback_reports (
                        report_id, case_id, request_id, normalized_url_hash, review_type,
                        employee_assessment, reason_code, comment, reported_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        report_id,
                        case_id,
                        request.request_id,
                        url_hash,
                        request.review_type,
                        request.employee_assessment,
                        request.reason_code,
                        request.comment,
                        reported_at,
                    ),
                )
                return ReportWebsiteResult(
                    report_id=report_id,
                    case_id=case_id,
                    duplicate=duplicate,
                    report_count=report_count,
                    reported_at=reported_at,
                )
        except FeedbackError:
            raise
        except sqlite3.Error as exc:
            raise FeedbackStorageError("failed to store feedback report") from exc

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with closing(self._connect()) as connection, connection:
            case = connection.execute("SELECT * FROM feedback_cases WHERE case_id = ?", (case_id,)).fetchone()
            if case is None:
                return None
            reports = connection.execute(
                """
                SELECT report_id, request_id, comment, reported_at
                , review_type, employee_assessment, reason_code
                FROM feedback_reports
                WHERE case_id = ?
                ORDER BY reported_at ASC
                """,
                (case_id,),
            ).fetchall()
            return {**dict(case), "reports": [dict(report) for report in reports]}

    def lookup_policy(self, normalized_url: str) -> dict[str, Any] | None:
        url_hash = hash_normalized_url(normalized_url)
        now = utc_now()
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                """
                SELECT
                    entry_id,
                    normalized_url,
                    list_type,
                    decision_reason,
                    screenshot_name,
                    screenshot_data_url,
                    source_case_id,
                    decided_by_email,
                    decided_by_name,
                    created_at,
                    updated_at,
                    expires_at
                FROM policy_entries
                WHERE normalized_url_hash = ?
                    AND (
                        list_type = 'blocklist'
                        OR expires_at IS NULL
                        OR expires_at > ?
                    )
                """,
                (url_hash, now),
            ).fetchone()
        return dict(row) if row is not None else None

    def list_policy_entries(self) -> list[dict[str, Any]]:
        now = utc_now()
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                """
                SELECT
                    entry_id,
                    normalized_url,
                    list_type,
                    decision_reason,
                    screenshot_name,
                    screenshot_data_url,
                    source_case_id,
                    decided_by_email,
                    decided_by_name,
                    created_at,
                    updated_at,
                    expires_at,
                    CASE
                        WHEN list_type = 'blocklist' THEN 'active'
                        WHEN expires_at IS NULL THEN 'permanent'
                        WHEN expires_at > ? THEN 'active'
                        ELSE 'expired'
                    END AS policy_status
                FROM policy_entries
                ORDER BY updated_at DESC
                """,
                (now,),
            ).fetchall()
        return [dict(row) for row in rows]

    def remove_policy_entry(self, entry_id: str) -> dict[str, Any] | None:
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                entry = connection.execute(
                    """
                    SELECT entry_id, normalized_url, list_type, source_case_id, expires_at
                    FROM policy_entries
                    WHERE entry_id = ?
                    """,
                    (entry_id,),
                ).fetchone()
                if entry is None:
                    return None
                connection.execute(
                    "DELETE FROM policy_entries WHERE entry_id = ?",
                    (entry_id,),
                )
                source_case_id = entry["source_case_id"]
                if source_case_id:
                    connection.execute(
                        """
                        UPDATE feedback_cases
                        SET
                            status = 'REOPENED',
                            admin_decision = NULL,
                            admin_reason = NULL,
                            admin_screenshot_name = NULL,
                            admin_screenshot_data_url = NULL,
                            admin_decided_at = NULL,
                            admin_decided_by_email = NULL,
                            admin_decided_by_name = NULL
                        WHERE case_id = ?
                        """,
                        (source_case_id,),
                    )
        except sqlite3.Error as exc:
            raise FeedbackStorageError("failed to remove policy entry") from exc
        return dict(entry)

    def resolve_case(
        self,
        *,
        case_id: str,
        decision: str,
        reason: str,
        decided_by_email: str,
        decided_by_name: str,
        screenshot_name: str | None = None,
        screenshot_data_url: str | None = None,
        allowlist_expiry_days: int | None = None,
    ) -> dict[str, Any]:
        if decision not in {"allowlist", "blocklist"}:
            raise CaseResolutionError("decision must be allowlist or blocklist")
        normalized_reason = reason.strip()
        if not normalized_reason:
            raise CaseResolutionError("A reason is required before updating the review list.")
        if len(normalized_reason) > 600:
            raise CaseResolutionError("The reason must contain at most 600 characters.")
        cleaned_screenshot_name = screenshot_name.strip() if isinstance(screenshot_name, str) and screenshot_name.strip() else None
        cleaned_screenshot_data_url = (
            screenshot_data_url.strip()
            if isinstance(screenshot_data_url, str) and screenshot_data_url.strip()
            else None
        )
        if cleaned_screenshot_data_url is not None and not cleaned_screenshot_data_url.startswith("data:image/"):
            raise CaseResolutionError("Screenshot evidence must be provided as an image upload.")
        if decision == "blocklist" and allowlist_expiry_days is not None:
            raise CaseResolutionError("An expiry period can only be set for an allowlist entry.")
        if allowlist_expiry_days is not None and (
            isinstance(allowlist_expiry_days, bool)
            or not isinstance(allowlist_expiry_days, int)
            or not 1 <= allowlist_expiry_days <= 365
        ):
            raise CaseResolutionError("Allowlist expiry must be between 1 and 365 days.")

        decided_at = utc_now()
        expires_at = (
            (datetime.now(timezone.utc) + timedelta(days=allowlist_expiry_days))
            .isoformat()
            .replace("+00:00", "Z")
            if decision == "allowlist" and allowlist_expiry_days is not None
            else None
        )
        case_status = "ALLOWLISTED" if decision == "allowlist" else "BLOCKLISTED"
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                case = connection.execute(
                    """
                    SELECT case_id, normalized_url, normalized_url_hash
                    FROM feedback_cases
                    WHERE case_id = ?
                    """,
                    (case_id,),
                ).fetchone()
                if case is None:
                    raise CaseResolutionError("The selected review case no longer exists.")
                entry_id = new_identifier("policy")
                connection.execute(
                    """
                    INSERT INTO policy_entries (
                        entry_id, normalized_url, normalized_url_hash, list_type,
                        decision_reason, screenshot_name, screenshot_data_url,
                        source_case_id, decided_by_email, decided_by_name,
                        created_at, updated_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(normalized_url_hash) DO UPDATE SET
                        normalized_url = excluded.normalized_url,
                        list_type = excluded.list_type,
                        decision_reason = excluded.decision_reason,
                        screenshot_name = excluded.screenshot_name,
                        screenshot_data_url = excluded.screenshot_data_url,
                        source_case_id = excluded.source_case_id,
                        decided_by_email = excluded.decided_by_email,
                        decided_by_name = excluded.decided_by_name,
                        updated_at = excluded.updated_at,
                        expires_at = excluded.expires_at
                    """,
                    (
                        entry_id,
                        case["normalized_url"],
                        case["normalized_url_hash"],
                        decision,
                        normalized_reason,
                        cleaned_screenshot_name,
                        cleaned_screenshot_data_url,
                        case_id,
                        decided_by_email,
                        decided_by_name,
                        decided_at,
                        decided_at,
                        expires_at,
                    ),
                )
                connection.execute(
                    """
                    UPDATE feedback_cases
                    SET
                        status = ?,
                        admin_decision = ?,
                        admin_reason = ?,
                        admin_screenshot_name = ?,
                        admin_screenshot_data_url = ?,
                        admin_decided_at = ?,
                        admin_decided_by_email = ?,
                        admin_decided_by_name = ?
                    WHERE case_id = ?
                    """,
                    (
                        case_status,
                        decision,
                        normalized_reason,
                        cleaned_screenshot_name,
                        cleaned_screenshot_data_url,
                        decided_at,
                        decided_by_email,
                        decided_by_name,
                        case_id,
                    ),
                )
        except FeedbackError:
            raise
        except sqlite3.Error as exc:
            raise FeedbackStorageError("failed to resolve feedback case") from exc

        resolved = self.get_case(case_id)
        if resolved is None:
            raise CaseResolutionError("The review case could not be reloaded after update.")
        return resolved

    def list_feedback_for_review(self) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                """
                SELECT
                    cases.case_id,
                    reports.report_id,
                    reports.request_id,
                    cases.normalized_url,
                    cases.model_version,
                    cases.risk_score,
                    cases.risk_category,
                    cases.status,
                    cases.report_count,
                    cases.admin_decision,
                    cases.admin_reason,
                    cases.admin_screenshot_name,
                    cases.admin_screenshot_data_url,
                    cases.admin_decided_at,
                    cases.admin_decided_by_email,
                    cases.admin_decided_by_name,
                    reports.comment,
                    reports.review_type,
                    reports.employee_assessment,
                    reports.reason_code,
                    reports.reported_at,
                    analysis.feature_schema_version,
                    analysis.features_json,
                    analysis.technical_reasons_json
                FROM feedback_cases AS cases
                JOIN feedback_reports AS reports ON reports.case_id = cases.case_id
                JOIN analysis_records AS analysis ON analysis.request_id = reports.request_id
                ORDER BY cases.last_reported_at DESC, reports.reported_at DESC
                """
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["features"] = json.loads(item.pop("features_json"))
            item["technicalReasons"] = json.loads(item.pop("technical_reasons_json"))
            item["reviewerLabel"] = None
            item["eligibleForTraining"] = False
            result.append(item)
        return result

    def counts(self) -> dict[str, int]:
        with closing(self._connect()) as connection, connection:
            case_count = int(connection.execute("SELECT COUNT(*) FROM feedback_cases").fetchone()[0])
            report_count = int(connection.execute("SELECT COUNT(*) FROM feedback_reports").fetchone()[0])
        return {"cases": case_count, "reports": report_count}


def hash_normalized_url(normalized_url: str) -> str:
    return hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()


def new_identifier(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
