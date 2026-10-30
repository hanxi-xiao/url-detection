from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

import joblib
import numpy as np
import pandas as pd

from .evaluation import positive_class_probability
from .risk import RiskThresholds, classify_risk


def _numeric_feature(record: Mapping[str, Any], name: str) -> float:
    value = record.get(name, 0.0)
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _has_trusted_official_identity(record: Mapping[str, Any]) -> bool:
    return any(
        (
            _numeric_feature(record, "IsKnownOfficialDomain") >= 1.0,
            _numeric_feature(record, "IsKnownOfficialSubdomain") >= 1.0,
        )
    )


def has_strong_phishing_evidence(record: Mapping[str, Any]) -> bool:
    trusted_official = _has_trusted_official_identity(record)
    independent_structural_signals = any(
        (
            _numeric_feature(record, "IsDomainIP") >= 1.0,
            _numeric_feature(record, "HasExternalFormSubmit") >= 1.0,
            _numeric_feature(record, "HasBrandImpersonation") >= 1.0,
            _numeric_feature(record, "BrandInDeceptivePosition") >= 1.0,
            _numeric_feature(record, "HasAtSymbol") >= 1.0,
            _numeric_feature(record, "IsShorteningService") >= 1.0
            and _numeric_feature(record, "RedirectCount") >= 1.0,
            _numeric_feature(record, "NoOfSubDomain") >= 3.0
            and _numeric_feature(record, "URLLength") >= 75.0,
            _numeric_feature(record, "RedirectCount") >= 3.0,
        )
    )
    if independent_structural_signals:
        return True
    if trusted_official:
        # Official SSO and account portals legitimately use login forms. Treat
        # credentials alone as insufficient unless an independent signal exists.
        return False
    return any(
        (
            _numeric_feature(record, "HasLoginForm") >= 1.0,
            _numeric_feature(record, "NoOfPasswordFields") >= 1.0,
        )
    )


def has_strong_benign_evidence(record: Mapping[str, Any]) -> bool:
    trusted_official = _has_trusted_official_identity(record)
    return all(
        (
            (
                _numeric_feature(record, "HTMLAvailable") >= 1.0
                and _numeric_feature(record, "DomainTitleMatch") >= 1.0
                and _numeric_feature(record, "TitleDomainTokenOverlap") >= 1.0
            )
            or (
                _numeric_feature(record, "IsKnownOfficialDomain") >= 1.0
                or _numeric_feature(record, "IsKnownOfficialSubdomain") >= 1.0
            ),
            _numeric_feature(record, "UsesHTTPS") >= 1.0,
            _numeric_feature(record, "IsDomainIP") <= 0.0,
            trusted_official or _numeric_feature(record, "HasSuspiciousPattern") <= 0.0,
            trusted_official or _numeric_feature(record, "SuspiciousPatternCount") <= 0.0,
            _numeric_feature(record, "HasBrandImpersonation") <= 0.0,
            _numeric_feature(record, "BrandInDeceptivePosition") <= 0.0,
            _numeric_feature(record, "HasAtSymbol") <= 0.0,
            _numeric_feature(record, "IsShorteningService") <= 0.0,
            trusted_official or _numeric_feature(record, "HasSensitiveKeyword") <= 0.0,
            trusted_official or _numeric_feature(record, "SensitiveKeywordCount") <= 0.0,
            trusted_official or _numeric_feature(record, "HasLongSensitivePath") <= 0.0,
            _numeric_feature(record, "NoOfPasswordFields") <= 0.0,
            _numeric_feature(record, "HasLoginForm") <= 0.0,
            _numeric_feature(record, "HasExternalFormSubmit") <= 0.0,
            _numeric_feature(record, "NoOfSubDomain") <= 1.0,
        )
    )


def apply_high_risk_guardrail(
    phishing_probability: float,
    record: Mapping[str, Any],
    thresholds: RiskThresholds,
) -> float:
    score = float(phishing_probability)
    if score < thresholds.high_risk:
        return score
    if has_strong_phishing_evidence(record):
        return score
    return min(score, thresholds.high_risk - 0.01)


def apply_missing_web_evidence_guardrail(
    risk_score: float,
    record: Mapping[str, Any],
    thresholds: RiskThresholds,
) -> float:
    score = float(risk_score)
    html_available = _numeric_feature(record, "HTMLAvailable")
    if html_available >= 1.0:
        return score
    if has_strong_phishing_evidence(record):
        return score
    if (
        _numeric_feature(record, "IsKnownOfficialDomain") >= 1.0
        or _numeric_feature(record, "IsKnownOfficialSubdomain") >= 1.0
    ):
        return min(score, thresholds.suspicious - 0.10)
    return min(score, thresholds.high_risk - 0.01)


def apply_benign_evidence_guardrail(
    risk_score: float,
    record: Mapping[str, Any],
    thresholds: RiskThresholds,
) -> float:
    score = float(risk_score)
    if not has_strong_benign_evidence(record):
        return score
    return min(score, thresholds.suspicious - 0.10)


@dataclass(frozen=True)
class PredictionResult:
    prediction: str
    predicted_class: int
    phishing_probability: float
    risk_score: float
    risk_score_percent: float
    risk_classification: str
    model_name: str
    model_version: str
    feature_contributions: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DetectionModelService:
    def __init__(self, bundle: Mapping[str, Any]) -> None:
        required = {"model", "model_name", "feature_names", "risk_thresholds"}
        missing = sorted(required - set(bundle))
        if missing:
            raise ValueError("Invalid model bundle: missing " + ", ".join(missing))
        self.model = bundle["model"]
        self.model_name = str(bundle["model_name"])
        self.model_version = str(bundle.get("model_version", self.model_name))
        self.feature_names = [str(name) for name in bundle["feature_names"]]
        self.thresholds = RiskThresholds.from_dict(bundle["risk_thresholds"])
        self.metadata = {key: value for key, value in bundle.items() if key != "model"}

    @classmethod
    def load(cls, model_path: str | Path) -> "DetectionModelService":
        path = Path(model_path)
        if not path.is_file():
            raise FileNotFoundError(f"Model file not found: {path}")
        return cls(joblib.load(path))

    def _coerce_records(self, rows: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        records = [dict(rows)] if isinstance(rows, Mapping) else [dict(row) for row in rows]
        if not records:
            raise ValueError("At least one feature row is required.")
        missing_by_row = [sorted(set(self.feature_names) - set(record)) for record in records]
        if any(missing_by_row):
            first_incomplete = next(index for index, missing in enumerate(missing_by_row) if missing)
            raise ValueError(
                f"Row {first_incomplete} is missing required features: {missing_by_row[first_incomplete]}"
            )
        return records

    def _prepare_rows(self, records: Sequence[Mapping[str, Any]]) -> pd.DataFrame:
        frame = pd.DataFrame(records).reindex(columns=self.feature_names)
        for column in frame.columns:
            frame[column] = pd.to_numeric(frame[column], errors="coerce")
        return frame.replace([np.inf, -np.inf], np.nan)

    def predict_many(self, rows: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> list[PredictionResult]:
        records = self._coerce_records(rows)
        frame = self._prepare_rows(records)
        probabilities = positive_class_probability(self.model, frame)
        predictions = (probabilities >= 0.5).astype(int)
        contribution_rows = self._local_feature_contributions(frame)
        results: list[PredictionResult] = []
        for index, (record, prediction, probability) in enumerate(zip(records, predictions, probabilities)):
            raw_score = float(probability)
            adjusted_score = apply_high_risk_guardrail(raw_score, record, self.thresholds)
            adjusted_score = apply_missing_web_evidence_guardrail(
                adjusted_score,
                record,
                self.thresholds,
            )
            adjusted_score = apply_benign_evidence_guardrail(
                adjusted_score,
                record,
                self.thresholds,
            )
            results.append(
                PredictionResult(
                    prediction="phishing" if prediction == 1 else "safe",
                    predicted_class=int(prediction),
                    phishing_probability=raw_score,
                    risk_score=adjusted_score,
                    risk_score_percent=round(adjusted_score * 100.0, 2),
                    risk_classification=classify_risk(adjusted_score, self.thresholds),
                    model_name=self.model_name,
                    model_version=self.model_version,
                    feature_contributions=contribution_rows[index],
                )
            )
        return results

    def predict_one(self, features: Mapping[str, Any]) -> PredictionResult:
        return self.predict_many(features)[0]

    def feature_importances(self) -> dict[str, float]:
        model = self.model
        if hasattr(model, "named_steps"):
            classifier = model.named_steps.get("classifier", model)
        else:
            classifier = model
        if hasattr(classifier, "feature_importances_"):
            values = [float(value) for value in classifier.feature_importances_]
        elif hasattr(classifier, "coef_"):
            coefficients = np.asarray(classifier.coef_, dtype=float)
            values = [float(abs(value)) for value in coefficients[0]]
        else:
            values = [1.0 for _ in self.feature_names]
        if len(values) != len(self.feature_names):
            values = [1.0 for _ in self.feature_names]
        return dict(zip(self.feature_names, values))

    def _local_feature_contributions(self, frame: pd.DataFrame) -> list[dict[str, float]]:
        """Return per-input XGBoost contributions when the active model supports them."""
        classifier = self.model
        if hasattr(self.model, "named_steps"):
            classifier = self.model.named_steps.get("classifier", self.model)
            imputer = self.model.named_steps.get("imputer")
            if imputer is not None:
                frame = pd.DataFrame(
                    imputer.transform(frame),
                    columns=self.feature_names,
                    index=frame.index,
                )

        if not hasattr(classifier, "get_booster"):
            return [{} for _ in range(len(frame))]

        try:
            from xgboost import DMatrix

            matrix = DMatrix(frame, feature_names=self.feature_names)
            contributions = classifier.get_booster().predict(matrix, pred_contribs=True)
        except Exception:
            return [{} for _ in range(len(frame))]

        return [
            {
                feature: float(value)
                for feature, value in zip(self.feature_names, row[:-1])
                if np.isfinite(value)
            }
            for row in contributions
        ]
