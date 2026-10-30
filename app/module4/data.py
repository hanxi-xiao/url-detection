from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from .feature_selection import MODEL_FEATURES
from app.module3.schema import FEATURE_BY_NAME


@dataclass(frozen=True)
class PreparedDataset:
    train_X: pd.DataFrame
    validation_X: pd.DataFrame
    test_X: pd.DataFrame
    train_y: pd.Series
    validation_y: pd.Series
    test_y: pd.Series
    rows_before_cleaning: int
    rows_after_cleaning: int
    source_rows: dict[str, int] | None = None

    @property
    def feature_names(self) -> list[str]:
        return list(self.train_X.columns)

    def summary(self) -> dict[str, object]:
        return {
            "rows_before_cleaning": self.rows_before_cleaning,
            "rows_after_cleaning": self.rows_after_cleaning,
            "feature_names": self.feature_names,
            "feature_count": len(self.feature_names),
            "train_rows": len(self.train_X),
            "validation_rows": len(self.validation_X),
            "test_rows": len(self.test_X),
            "phishing_train_rows": int(self.train_y.sum()),
            "safe_train_rows": int((1 - self.train_y).sum()),
            "source_rows": self.source_rows or {},
        }


def load_dataset(csv_path: str | Path) -> pd.DataFrame:
    frame = pd.read_csv(csv_path)
    if frame.empty:
        raise ValueError("Dataset is empty.")
    return frame


def load_datasets(csv_paths: list[str | Path]) -> tuple[pd.DataFrame, dict[str, int]]:
    if not csv_paths:
        raise ValueError("At least one dataset path is required.")
    frames: list[pd.DataFrame] = []
    source_rows: dict[str, int] = {}
    for csv_path in csv_paths:
        path = Path(csv_path)
        frame = load_dataset(path)
        frames.append(frame)
        source_rows[path.name] = len(frame)
    return pd.concat(frames, ignore_index=True), source_rows


def prepare_dataset(
    csv_path: str | Path,
    extra_csv_paths: list[str | Path] | None = None,
    validation_size: float = 0.10,
    test_size: float = 0.20,
    random_state: int = 42,
) -> PreparedDataset:
    if not 0.0 < validation_size < 1.0 or not 0.0 < test_size < 1.0:
        raise ValueError("validation_size and test_size must be between 0 and 1.")
    if validation_size + test_size >= 1.0:
        raise ValueError("validation_size + test_size must be less than 1.")

    input_paths = [csv_path, *(extra_csv_paths or [])]
    frame, source_rows = load_datasets(input_paths)
    frame = frame.drop_duplicates().copy()
    rows_before = len(frame)
    if "label" not in frame.columns:
        raise ValueError("Dataset is missing required column: label")
    for name in MODEL_FEATURES:
        if name not in frame.columns:
            frame[name] = FEATURE_BY_NAME[name].default

    frame = frame.loc[:, [*MODEL_FEATURES, "label"]].copy()
    for name in MODEL_FEATURES:
        frame[name] = pd.to_numeric(frame[name], errors="coerce")
    frame["label"] = pd.to_numeric(frame["label"], errors="coerce")
    frame = frame.replace([np.inf, -np.inf], np.nan)
    frame = frame.dropna(subset=["label"]).copy()
    frame["label"] = frame["label"].astype(int)
    if set(frame["label"].unique()) - {0, 1}:
        raise ValueError("Labels must use 0=safe and 1=phishing.")
    if frame["label"].nunique() != 2:
        raise ValueError("Dataset must contain both safe and phishing rows.")

    X = frame.loc[:, MODEL_FEATURES]
    y = frame["label"]

    train_X, temp_X, train_y, temp_y = train_test_split(
        X,
        y,
        test_size=validation_size + test_size,
        random_state=random_state,
        stratify=y,
    )
    relative_test_size = test_size / (validation_size + test_size)
    validation_X, test_X, validation_y, test_y = train_test_split(
        temp_X,
        temp_y,
        test_size=relative_test_size,
        random_state=random_state,
        stratify=temp_y,
    )

    return PreparedDataset(
        train_X=train_X.reset_index(drop=True),
        validation_X=validation_X.reset_index(drop=True),
        test_X=test_X.reset_index(drop=True),
        train_y=train_y.reset_index(drop=True),
        validation_y=validation_y.reset_index(drop=True),
        test_y=test_y.reset_index(drop=True),
        rows_before_cleaning=rows_before,
        rows_after_cleaning=len(frame),
        source_rows=source_rows,
    )
