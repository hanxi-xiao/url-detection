from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from app.config import ARTIFACTS_DIR
from app.module3.url_features import extract_domain_identity_features
from app.module6.evaluation import comparison_table, generate_report
from app.module6.log_manager import generate_statistics, get_detection_history
from app.module6.model_manager import load_model_information
from app.services.state import feedback_repository


def build_cases() -> list[dict[str, Any]]:
    review_rows = feedback_repository.list_feedback_for_review()
    cases_by_url: dict[str, dict[str, Any]] = {}
    for row in review_rows:
        normalized_url = str(row["normalized_url"])
        case = cases_by_url.get(normalized_url)
        if case is None:
            case = {
                "caseId": row["case_id"],
                "requestId": row["request_id"],
                "url": normalized_url,
                "riskScore": round(float(row["risk_score"])),
                "riskCategory": row["risk_category"],
                "status": row["status"],
                "adminDecision": row["admin_decision"],
                "adminReason": row["admin_reason"],
                "adminScreenshotName": row["admin_screenshot_name"],
                "adminScreenshotDataUrl": row["admin_screenshot_data_url"],
                "adminDecidedAt": row["admin_decided_at"],
                "adminDecidedByEmail": row["admin_decided_by_email"],
                "adminDecidedByName": row["admin_decided_by_name"],
                "reportCount": 0,
                "modelVersion": row["model_version"],
                "lastReportedAt": row["reported_at"],
                "reports": [],
                "modelVersions": [],
            }
            cases_by_url[normalized_url] = case
        report_id = str(row["report_id"])
        if report_id in {report["reportId"] for report in case["reports"]}:
            continue
        case["reportCount"] += 1
        case["reports"].append(
            {
                "reportId": report_id,
                "reviewType": row["review_type"],
                "employeeAssessment": row["employee_assessment"],
                "reasonCode": row["reason_code"],
                "comment": row["comment"],
                "reportedAt": row["reported_at"],
            }
        )
        if row["model_version"] not in case["modelVersions"]:
            case["modelVersions"].append(row["model_version"])
        if row["reported_at"] > case["lastReportedAt"]:
            case["lastReportedAt"] = row["reported_at"]
            case["caseId"] = row["case_id"]
            case["requestId"] = row["request_id"]
            case["modelVersion"] = row["model_version"]
            case["riskScore"] = round(float(row["risk_score"]))
            case["riskCategory"] = row["risk_category"]
            case["status"] = row["status"]
            case["adminDecision"] = row["admin_decision"]
            case["adminReason"] = row["admin_reason"]
            case["adminScreenshotName"] = row["admin_screenshot_name"]
            case["adminScreenshotDataUrl"] = row["admin_screenshot_data_url"]
            case["adminDecidedAt"] = row["admin_decided_at"]
            case["adminDecidedByEmail"] = row["admin_decided_by_email"]
            case["adminDecidedByName"] = row["admin_decided_by_name"]
    cases = list(cases_by_url.values())
    cases.sort(key=lambda item: item["lastReportedAt"], reverse=True)
    return cases


def build_overview() -> dict[str, Any]:
    stats = generate_statistics()
    cases = build_cases()
    models = load_model_information(limit=None)
    active_model = models.iloc[0].to_dict() if not models.empty else None
    return {
        "summary": {
            "totalScans": stats["total_analyzed_urls"],
            "safeCount": stats["safe_urls"],
            "suspiciousCount": stats["suspicious_urls"],
            "highRiskCount": stats["high_risk_urls"],
            "reportedCount": sum(case["reportCount"] for case in cases),
            "openCaseCount": sum(case["status"] in {"NEW", "REOPENED"} for case in cases),
            "allowlistedCount": sum(case["status"] == "ALLOWLISTED" for case in cases),
            "blocklistedCount": sum(case["status"] == "BLOCKLISTED" for case in cases),
            "averageRiskScore": stats["average_risk_score"],
            "averageResponseMs": stats["average_response_ms"],
        },
        "recentCases": cases[:10],
        "activeModel": (
            {
                "version": active_model["version"],
                "algorithm": active_model["model_name"],
                "createdAt": active_model["created_at"],
            }
            if active_model
            else None
        ),
        "evaluationSummary": generate_report(),
    }


def build_review_insights() -> dict[str, Any]:
    rows = feedback_repository.list_feedback_for_review()
    cases = build_cases()
    reason_counts: dict[str, int] = {}
    review_type_counts: dict[str, int] = {}
    for row in rows:
        reason_code = str(row.get("reason_code") or "other")
        review_type = str(row.get("review_type") or "request_recheck")
        reason_counts[reason_code] = reason_counts.get(reason_code, 0) + 1
        review_type_counts[review_type] = review_type_counts.get(review_type, 0) + 1

    top_reasons = [
        {"reasonCode": code, "count": count}
        for code, count in sorted(
            reason_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )[:6]
    ]
    return {
        "summary": {
            "openCases": sum(case["status"] in {"NEW", "REOPENED"} for case in cases),
            "allowlisted": sum(case["status"] == "ALLOWLISTED" for case in cases),
            "blocklisted": sum(case["status"] == "BLOCKLISTED" for case in cases),
            "totalReports": len(rows),
        },
        "reviewTypes": [
            {"reviewType": review_type, "count": count}
            for review_type, count in sorted(review_type_counts.items())
        ],
        "topReasons": top_reasons,
    }


def build_brand_impersonation_visuals() -> dict[str, Any]:
    """Create administrator-facing identity evidence from stored scan URLs only."""
    history = get_detection_history(limit=None)
    seen_urls: set[str] = set()
    items: list[dict[str, Any]] = []
    for _, row in history.iterrows():
        url = str(row["normalized_url"])
        if url in seen_urls:
            continue
        seen_urls.add(url)
        features, identity = extract_domain_identity_features(url)
        impersonated_domain = identity.get("impersonatedDomain")
        if not impersonated_domain:
            continue
        techniques = list(identity.get("impersonationTechniques") or [])
        items.append(
            {
                "url": url,
                "observedDomain": identity.get("registrableDomain"),
                "targetBrand": identity.get("impersonatedBrand"),
                "targetDomain": impersonated_domain,
                "similarityScore": round(float(features.get("BrandSimilarityScore", 0.0)) * 100),
                "techniques": techniques,
                "digitSubstitutions": identity.get("digitLetterSubstitutions") or [],
                "effectiveRegistrableDomain": identity.get("effectiveRegistrableDomain"),
                "riskCategory": str(row["risk_label"]),
                "safetyScore": round(100.0 - float(row["risk_score"])),
                "lastSeenAt": str(row["created_at"]),
            }
        )
    items.sort(key=lambda item: (item["similarityScore"], item["lastSeenAt"]), reverse=True)
    brands = {str(item["targetDomain"]) for item in items}
    digit_substitution_count = sum(
        "digit_letter_substitution" in item["techniques"] for item in items
    )
    return {
        "summary": {
            "detectedDomains": len(items),
            "targetedBrands": len(brands),
            "digitSubstitutionCases": digit_substitution_count,
        },
        "items": items,
    }


def paginate(items: list[dict[str, Any]], page: int, page_size: int) -> dict[str, Any]:
    total_items = len(items)
    total_pages = max(1, math.ceil(total_items / page_size))
    page = min(max(1, page), total_pages)
    start = (page - 1) * page_size
    return {
        "items": items[start : start + page_size],
        "pagination": {
            "page": page,
            "pageSize": page_size,
            "totalItems": total_items,
            "totalPages": total_pages,
        },
    }


def build_model_metrics(model_version: str | None = None) -> dict[str, Any] | None:
    records = comparison_table()
    if records.empty:
        report_path = ARTIFACTS_DIR / "training_report.json"
        if not report_path.exists():
            return None
        report = json.loads(report_path.read_text(encoding="utf-8"))
        best_model = str(report["best_model"])
        metrics = report["test_metrics"][best_model]
        version = str(report["model_version"])
        if model_version is not None and version != model_version:
            return None
        return {
            "modelVersion": version,
            "algorithm": best_model,
            "dataset": "test",
            "metrics": {
                "accuracy": float(metrics["accuracy"]),
                "precision": float(metrics["precision"]),
                "recall": float(metrics["recall"]),
                "f1Score": float(metrics["f1"]),
                "rocAuc": float(metrics["roc_auc"]),
                "falsePositiveRate": float(metrics["false_positive_rate"]),
                "falseNegativeRate": float(metrics["false_negative_rate"]),
                "averageInferenceMs": float(metrics["average_inference_ms"]),
            },
        }
    if model_version is not None:
        records = records[records["version"] == model_version]
    if records.empty:
        return None
    test_rows = records[records["split_name"] == "test"]
    selected = test_rows.iloc[0] if not test_rows.empty else records.iloc[0]
    return {
        "modelVersion": selected["version"],
        "algorithm": selected["model_name"],
        "dataset": selected["split_name"],
        "metrics": {
            "accuracy": float(selected["accuracy"]),
            "precision": float(selected["precision"]),
            "recall": float(selected["recall"]),
            "f1Score": float(selected["f1_score"]),
            "rocAuc": float(selected["roc_auc"]),
            "falsePositiveRate": float(selected["false_positive_rate"]),
            "falseNegativeRate": float(selected["false_negative_rate"]),
            "averageInferenceMs": float(selected["average_inference_ms"]),
        },
    }
