from __future__ import annotations

from pathlib import Path

import pandas as pd

from app.config import DEFAULT_FEEDBACK_DATASET
from app.services.state import feedback_repository


def prepare_retraining_data(reviewed_only: bool = False) -> pd.DataFrame:
    rows = feedback_repository.list_feedback_for_review()
    if not rows:
        return pd.DataFrame(
            columns=[
                "case_id",
                "report_id",
                "request_id",
                "normalized_url",
                "model_version",
                "risk_score",
                "risk_category",
                "status",
                "report_count",
                "comment",
                "reported_at",
                "feature_schema_version",
                "features",
                "technicalReasons",
                "reviewerLabel",
                "eligibleForTraining",
            ]
        )
    frame = pd.DataFrame(rows)
    if reviewed_only:
        frame = frame[frame["eligibleForTraining"] == True]  # noqa: E712
    return frame.reset_index(drop=True)


def export_feedback_dataset(output_path: str | None = None, reviewed_only: bool = False) -> Path:
    dataset = prepare_retraining_data(reviewed_only=reviewed_only)
    destination = Path(output_path) if output_path else DEFAULT_FEEDBACK_DATASET
    destination.parent.mkdir(parents=True, exist_ok=True)
    dataset.to_csv(destination, index=False)
    return destination
