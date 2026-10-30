from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .schema import FEATURE_SCHEMA_VERSION


@dataclass(slots=True)
class ProcessedURLData:
    request_id: str
    normalized_url: str
    raw_url: str | None = None
    html: str | None = None
    final_url: str | None = None
    redirect_chain: list[str] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ProcessedURLData":
        request_id = value.get("requestId", value.get("request_id", ""))
        normalized_url = value.get("normalizedUrl", value.get("normalized_url"))
        raw_url = value.get("rawUrl", value.get("raw_url"))
        final_url = value.get("finalUrl", value.get("final_url"))
        redirect_chain = value.get("redirectChain", value.get("redirect_chain", []))
        fetch_status = value.get("fetchStatus", value.get("fetch_status"))

        if not isinstance(request_id, str):
            raise TypeError("requestId must be a string")
        if not isinstance(normalized_url, str) or not normalized_url.strip():
            raise ValueError("normalizedUrl must be a non-empty string")
        if raw_url is not None and not isinstance(raw_url, str):
            raise TypeError("rawUrl must be a string or null")
        if final_url is not None and not isinstance(final_url, str):
            raise TypeError("finalUrl must be a string or null")
        if redirect_chain is None:
            redirect_chain = []
        if not isinstance(redirect_chain, list) or not all(isinstance(item, str) for item in redirect_chain):
            raise TypeError("redirectChain must be an array of strings")

        html = value.get("html")
        if html is not None and not isinstance(html, str):
            raise TypeError("html must be a string or null")
        if fetch_status is not None and not isinstance(fetch_status, str):
            raise TypeError("fetchStatus must be a string or null")

        return cls(
            request_id=request_id,
            normalized_url=normalized_url.strip(),
            raw_url=raw_url,
            html=html,
            final_url=final_url,
            redirect_chain=list(redirect_chain),
        )


@dataclass(slots=True)
class FeatureQualityReport:
    is_valid: bool
    missing_features: list[str]
    imputed_features: list[str]
    out_of_range_features: list[str]
    warnings: list[str]

    def to_api_dict(self) -> dict[str, Any]:
        return {
            "isValid": self.is_valid,
            "missingFeatures": self.missing_features,
            "imputedFeatures": self.imputed_features,
            "outOfRangeFeatures": self.out_of_range_features,
            "warnings": self.warnings,
        }


@dataclass(slots=True)
class FeatureExtractionResult:
    request_id: str
    normalized_url: str
    features: dict[str, float]
    normalized_features: dict[str, float]
    feature_order: list[str]
    feature_vector: list[float]
    quality: FeatureQualityReport
    evidence: dict[str, Any] = field(default_factory=dict)
    feature_schema_version: str = FEATURE_SCHEMA_VERSION

    def to_api_dict(self) -> dict[str, Any]:
        return {
            "requestId": self.request_id,
            "normalizedUrl": self.normalized_url,
            "featureSchemaVersion": self.feature_schema_version,
            "features": self.features,
            "normalizedFeatures": self.normalized_features,
            "featureOrder": self.feature_order,
            "featureVector": self.feature_vector,
            "quality": self.quality.to_api_dict(),
            "evidence": self.evidence,
        }
