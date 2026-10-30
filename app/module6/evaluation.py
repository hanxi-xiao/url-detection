from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

import pandas as pd

from app.config import DEFAULT_MODEL_RECORD_DB
from app.module6.database import get_connection, initialize_databases
from app.module6.model_manager import load_evaluation_information


def save_training_report(report: Mapping[str, Any]) -> None:
    initialize_databases()
    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    model_name = str(report["best_model"])
    version = str(report["model_version"])
    dataset_version = str(report["dataset_version"])
    selection_metric = str(report["selection_metric"])
    test_metrics = report["test_metrics"][model_name]
    validation_metrics = report["validation_metrics"][model_name]

    with get_connection(DEFAULT_MODEL_RECORD_DB) as connection:
        connection.execute("DELETE FROM evaluation_records WHERE version = ?", (version,))
        connection.execute(
            """
            INSERT INTO model_records (
                model_name,
                version,
                dataset_version,
                selection_metric,
                accuracy,
                precision,
                recall,
                f1_score,
                roc_auc,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(version) DO UPDATE SET
                model_name=excluded.model_name,
                dataset_version=excluded.dataset_version,
                selection_metric=excluded.selection_metric,
                accuracy=excluded.accuracy,
                precision=excluded.precision,
                recall=excluded.recall,
                f1_score=excluded.f1_score,
                roc_auc=excluded.roc_auc,
                created_at=excluded.created_at
            """,
            (
                model_name,
                version,
                dataset_version,
                selection_metric,
                float(test_metrics["accuracy"]),
                float(test_metrics["precision"]),
                float(test_metrics["recall"]),
                float(test_metrics["f1"]),
                float(test_metrics["roc_auc"]),
                created_at,
            ),
        )
        for split_name, metrics_by_model in (
            ("validation", report["validation_metrics"]),
            ("test", report["test_metrics"]),
        ):
            for candidate_name, metrics in metrics_by_model.items():
                connection.execute(
                    """
                    INSERT INTO evaluation_records (
                        model_name,
                        version,
                        split_name,
                        accuracy,
                        precision,
                        recall,
                        f1_score,
                        roc_auc,
                        false_positive_rate,
                        false_negative_rate,
                        average_inference_ms,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        candidate_name,
                        version,
                        split_name,
                        float(metrics["accuracy"]),
                        float(metrics["precision"]),
                        float(metrics["recall"]),
                        float(metrics["f1"]),
                        float(metrics["roc_auc"]),
                        float(metrics["false_positive_rate"]),
                        float(metrics["false_negative_rate"]),
                        float(metrics["average_inference_ms"]),
                        created_at,
                    ),
                )


def generate_report() -> dict[str, float | int | str | None]:
    records = load_evaluation_information()
    if records.empty:
        return {
            "total_evaluations": 0,
            "best_model": None,
            "best_f1_score": 0.0,
            "best_roc_auc": 0.0,
        }
    test_records = records[records["split_name"] == "test"]
    if test_records.empty:
        test_records = records
    top_record = test_records.sort_values(by=["f1_score", "roc_auc", "created_at"], ascending=[False, False, False]).iloc[0]
    return {
        "total_evaluations": int(len(records)),
        "best_model": f"{top_record['model_name']} {top_record['version']}",
        "best_f1_score": float(top_record["f1_score"]),
        "best_roc_auc": float(test_records["roc_auc"].max()),
    }


def comparison_table() -> pd.DataFrame:
    records = load_evaluation_information()
    if records.empty:
        return records
    return records.sort_values(by=["created_at", "split_name", "f1_score"], ascending=[False, True, False]).reset_index(drop=True)
