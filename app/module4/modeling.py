from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .evaluation import evaluate_binary_classifier
from .risk import RiskThresholds


@dataclass(frozen=True)
class TrainingOutcome:
    best_model_name: str
    best_model: Any
    validation_metrics: dict[str, dict[str, Any]]
    test_metrics: dict[str, dict[str, Any]]
    skipped_models: dict[str, str]


def build_models(random_state: int = 42) -> tuple[dict[str, Any], dict[str, str]]:
    models: dict[str, Any] = {
        "logistic_regression": Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
                (
                    "classifier",
                    LogisticRegression(
                        max_iter=2_000,
                        class_weight="balanced",
                        random_state=random_state,
                    ),
                ),
            ]
        ),
        "random_forest": Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="median")),
                (
                    "classifier",
                    RandomForestClassifier(
                        n_estimators=400,
                        min_samples_leaf=2,
                        class_weight="balanced",
                        random_state=random_state,
                        n_jobs=-1,
                    ),
                ),
            ]
        ),
    }
    skipped: dict[str, str] = {}
    try:
        from xgboost import XGBClassifier
    except ImportError:
        skipped["xgboost"] = "xgboost is not installed."
    else:
        models["xgboost"] = Pipeline(
            steps=[
                ("imputer", SimpleImputer(strategy="median")),
                (
                    "classifier",
                    XGBClassifier(
                        n_estimators=350,
                        max_depth=5,
                        learning_rate=0.05,
                        subsample=0.85,
                        colsample_bytree=0.85,
                        objective="binary:logistic",
                        eval_metric="logloss",
                        random_state=random_state,
                        n_jobs=-1,
                    ),
                ),
            ]
        )
    return models, skipped


def train_and_compare(
    train_X,
    train_y,
    validation_X,
    validation_y,
    test_X,
    test_y,
    selection_metric: str = "f1",
    random_state: int = 42,
) -> TrainingOutcome:
    allowed_metrics = {"accuracy", "precision", "recall", "f1", "roc_auc"}
    if selection_metric not in allowed_metrics:
        raise ValueError("Unsupported selection metric.")
    models, skipped = build_models(random_state=random_state)
    fitted_models: dict[str, Any] = {}
    validation_metrics: dict[str, dict[str, Any]] = {}
    test_metrics: dict[str, dict[str, Any]] = {}
    for name, model in models.items():
        model.fit(train_X, train_y)
        fitted_models[name] = model
        validation_metrics[name] = evaluate_binary_classifier(model, validation_X, validation_y)
        test_metrics[name] = evaluate_binary_classifier(model, test_X, test_y)

    best_name = max(
        validation_metrics,
        key=lambda name: (
            validation_metrics[name][selection_metric],
            validation_metrics[name]["roc_auc"],
            validation_metrics[name]["f1"],
        ),
    )
    return TrainingOutcome(
        best_model_name=best_name,
        best_model=fitted_models[best_name],
        validation_metrics=validation_metrics,
        test_metrics=test_metrics,
        skipped_models=skipped,
    )


def save_model_bundle(
    output_path: str | Path,
    outcome: TrainingOutcome,
    feature_names: list[str],
    thresholds: RiskThresholds,
    dataset_summary: dict[str, object],
    selection_metric: str,
    random_state: int,
    model_version: str,
    dataset_version: str,
) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    bundle = {
        "artifact_version": 1,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "model_name": outcome.best_model_name,
        "model_version": model_version,
        "dataset_version": dataset_version,
        "model": outcome.best_model,
        "feature_names": feature_names,
        "risk_thresholds": thresholds.to_dict(),
        "validation_metrics": outcome.validation_metrics,
        "test_metrics": outcome.test_metrics,
        "skipped_models": outcome.skipped_models,
        "dataset_summary": dataset_summary,
        "selection_metric": selection_metric,
        "random_state": random_state,
        "class_definition": {"0": "safe", "1": "phishing"},
    }
    joblib.dump(bundle, path)
    return path
