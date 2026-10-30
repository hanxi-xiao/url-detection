from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import pandas as pd

from app.config import DEFAULT_PREDICTION_LOG_DB
from app.module6.database import get_connection, initialize_databases


def save_prediction_log(
    *,
    request_id: str,
    normalized_url: str,
    risk_score: float,
    risk_label: str,
    phishing_probability: float,
    model_name: str,
    model_version: str,
    response_ms: Optional[float] = None,
    created_at: Optional[str] = None,
) -> int:
    initialize_databases()
    logged_at = created_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    with get_connection(DEFAULT_PREDICTION_LOG_DB) as connection:
        cursor = connection.execute(
            """
            INSERT INTO prediction_logs (
                request_id,
                normalized_url,
                risk_score,
                risk_label,
                phishing_probability,
                model_name,
                model_version,
                response_ms,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                normalized_url,
                risk_score,
                risk_label,
                phishing_probability,
                model_name,
                model_version,
                response_ms,
                logged_at,
            ),
        )
        return int(cursor.lastrowid)


def get_detection_history(
    risk_label: Optional[str] = None,
    limit: Optional[int] = 100,
) -> pd.DataFrame:
    initialize_databases()
    query = "SELECT * FROM prediction_logs WHERE 1 = 1"
    parameters: list[object] = []
    if risk_label:
        query += " AND risk_label = ?"
        parameters.append(risk_label)
    query += " ORDER BY created_at DESC, id DESC"
    if limit:
        query += " LIMIT ?"
        parameters.append(limit)
    with get_connection(DEFAULT_PREDICTION_LOG_DB) as connection:
        return pd.read_sql_query(query, connection, params=parameters)


def generate_statistics() -> dict[str, float | int]:
    history = get_detection_history(limit=None)
    if history.empty:
        return {
            "total_analyzed_urls": 0,
            "safe_urls": 0,
            "suspicious_urls": 0,
            "high_risk_urls": 0,
            "average_risk_score": 0.0,
            "average_response_ms": 0.0,
        }
    normalized_labels = history["risk_label"].astype(str).str.strip().str.lower()
    return {
        "total_analyzed_urls": int(len(history)),
        "safe_urls": int((normalized_labels == "safe").sum()),
        "suspicious_urls": int((normalized_labels == "suspicious").sum()),
        "high_risk_urls": int((normalized_labels == "high risk").sum()),
        "average_risk_score": round(float(history["risk_score"].mean()), 2),
        "average_response_ms": round(float(history["response_ms"].fillna(0).mean()), 3),
    }
