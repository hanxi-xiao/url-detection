"""Stable data contracts for Module 5."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Mapping


class RiskCategory(str, Enum):
    SAFE = "Safe"
    SUSPICIOUS = "Suspicious"
    HIGH_RISK = "High Risk"


class ExplanationDirection(str, Enum):
    INCREASES_RISK = "increases_risk"
    DECREASES_RISK = "decreases_risk"


@dataclass(frozen=True, slots=True)
class PredictionContext:
    request_id: str
    normalized_url: str
    model_version: str
    feature_schema_version: str
    features: dict[str, float | str | None]
    phishing_probability: float
    risk_score: float
    risk_category: RiskCategory
    evidence: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "PredictionContext":
        request_id = _required_text(value, "requestId")
        normalized_url = _required_text(value, "normalizedUrl")
        model_version = _required_text(value, "modelVersion")
        feature_schema_version = _required_text(value, "featureSchemaVersion")
        raw_features = value.get("features")
        if not isinstance(raw_features, Mapping) or not raw_features:
            raise ValueError("features must be a non-empty object")

        features: dict[str, float | str | None] = {}
        for raw_name, raw_feature_value in raw_features.items():
            name = str(raw_name).strip()
            if not name:
                raise ValueError("feature names must be non-empty strings")
            if raw_feature_value is None or isinstance(raw_feature_value, str):
                features[name] = raw_feature_value
                continue
            if isinstance(raw_feature_value, (int, float, bool)):
                numeric = float(raw_feature_value)
                if not math.isfinite(numeric):
                    raise ValueError(f"feature {name} must be finite")
                features[name] = numeric
                continue
            raise TypeError(f"feature {name} has an unsupported value")

        probability = _bounded_number(
            value.get("phishingProbability"),
            "phishingProbability",
            minimum=0.0,
            maximum=1.0,
        )
        risk_score = _bounded_number(
            value.get("riskScore"),
            "riskScore",
            minimum=0.0,
            maximum=100.0,
        )
        try:
            risk_category = RiskCategory(value.get("riskCategory"))
        except ValueError as exc:
            raise ValueError(
                "riskCategory must be Safe, Suspicious, or High Risk"
            ) from exc
        raw_evidence = value.get("evidence", {})
        if not isinstance(raw_evidence, Mapping):
            raise TypeError("evidence must be an object")

        return cls(
            request_id=request_id,
            normalized_url=normalized_url,
            model_version=model_version,
            feature_schema_version=feature_schema_version,
            features=features,
            phishing_probability=probability,
            risk_score=risk_score,
            risk_category=risk_category,
            evidence=dict(raw_evidence),
        )


@dataclass(frozen=True, slots=True)
class FeatureImpact:
    feature: str
    value: float | str | None
    impact: float
    direction: ExplanationDirection

    @classmethod
    def from_value(cls, feature: str, value: float | str | None, impact: float) -> "FeatureImpact":
        numeric_impact = float(impact)
        if not math.isfinite(numeric_impact):
            raise ValueError("feature impact must be finite")
        direction = (
            ExplanationDirection.INCREASES_RISK
            if numeric_impact >= 0.0
            else ExplanationDirection.DECREASES_RISK
        )
        return cls(
            feature=str(feature),
            value=value,
            impact=numeric_impact,
            direction=direction,
        )


@dataclass(frozen=True, slots=True)
class EmployeeReason:
    title: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class TechnicalReason:
    feature: str
    value: float | str | None
    impact: float
    direction: ExplanationDirection
    title: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature": self.feature,
            "value": self.value,
            "impact": self.impact,
            "direction": self.direction.value,
            "title": self.title,
            "detail": self.detail,
        }

    def to_employee_reason(self) -> EmployeeReason:
        return EmployeeReason(title=self.title, detail=self.detail)


@dataclass(frozen=True, slots=True)
class ExplainabilityResult:
    request_id: str
    model_version: str
    reasons: tuple[TechnicalReason, ...]
    recommendations: tuple[str, ...]
    explanation_ms: float

    def to_internal_dict(self) -> dict[str, Any]:
        return {
            "requestId": self.request_id,
            "modelVersion": self.model_version,
            "reasons": [reason.to_dict() for reason in self.reasons],
            "recommendations": list(self.recommendations),
            "explanationMs": round(self.explanation_ms, 3),
        }

    def to_employee_fields(self) -> dict[str, Any]:
        return {
            "reasons": [reason.to_employee_reason().to_dict() for reason in self.reasons],
            "recommendations": list(self.recommendations),
        }


@dataclass(frozen=True, slots=True)
class ReportWebsiteRequest:
    request_id: str
    url: str
    review_type: str
    employee_assessment: str
    reason_code: str
    comment: str | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ReportWebsiteRequest":
        request_id = _required_text(value, "requestId")
        url = _required_text(value, "url")
        review_type = _required_text(value, "reviewType")
        employee_assessment = _required_text(value, "employeeAssessment")
        reason_code = _required_text(value, "reasonCode")
        allowed_review_types = {"report_suspicious", "request_recheck"}
        if review_type not in allowed_review_types:
            raise ValueError("reviewType must be report_suspicious or request_recheck")
        try:
            risk_category = RiskCategory(employee_assessment)
        except ValueError as exc:
            raise ValueError(
                "employeeAssessment must be Safe, Suspicious, or High Risk"
            ) from exc
        if review_type == "report_suspicious" and risk_category == RiskCategory.SAFE:
            raise ValueError(
                "employeeAssessment cannot be Safe when reviewType is report_suspicious"
            )
        raw_comment = value.get("comment")
        if raw_comment is None:
            comment = None
        elif not isinstance(raw_comment, str):
            raise TypeError("comment must be a string or null")
        else:
            comment = raw_comment.strip() or None
        if comment is not None and len(comment) > 400:
            raise ValueError("comment must contain at most 400 characters")
        return cls(
            request_id=request_id,
            url=url,
            review_type=review_type,
            employee_assessment=employee_assessment,
            reason_code=reason_code,
            comment=comment,
        )


@dataclass(frozen=True, slots=True)
class ReportWebsiteResult:
    report_id: str
    case_id: str
    duplicate: bool
    report_count: int
    reported_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "reportId": self.report_id,
            "caseId": self.case_id,
            "duplicate": self.duplicate,
            "reportCount": self.report_count,
            "reportedAt": self.reported_at,
        }


@dataclass(frozen=True, slots=True)
class APIResponse:
    status_code: int
    body: dict[str, Any]


def _required_text(value: Mapping[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return item.strip()


def _bounded_number(value: Any, name: str, *, minimum: float, maximum: float) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"{name} must be a number") from exc
    if not math.isfinite(numeric) or not minimum <= numeric <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return numeric
