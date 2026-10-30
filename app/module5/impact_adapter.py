"""Approximate feature-impact adapter for current Module 4 models."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .models import FeatureImpact


RISK_ORIENTATION: dict[str, str] = {
    "URLLength": "high_risk_when_high",
    "DomainLength": "high_risk_when_high",
    "NoOfSpecialCharsInURL": "high_risk_when_high",
    "IsDomainIP": "high_risk_when_high",
    "NoOfSubDomain": "high_risk_when_high",
    "HasSuspiciousPattern": "high_risk_when_high",
    "SuspiciousPatternCount": "high_risk_when_high",
    "BrandSimilarityScore": "high_risk_when_high",
    "HasBrandImpersonation": "high_risk_when_high",
    "IsKnownOfficialDomain": "high_risk_when_low",
    "IsKnownOfficialSubdomain": "high_risk_when_low",
    "BrandInDeceptivePosition": "high_risk_when_high",
    "HasAtSymbol": "high_risk_when_high",
    "IsShorteningService": "high_risk_when_high",
    "HasSensitiveKeyword": "high_risk_when_high",
    "SensitiveKeywordCount": "high_risk_when_high",
    "HasLongSensitivePath": "high_risk_when_high",
    "UsesHTTPS": "high_risk_when_low",
    "HTMLAvailable": "high_risk_when_low",
    "HasTitle": "high_risk_when_low",
    "TitleLength": "high_risk_when_high",
    "HTMLLength": "high_risk_when_high",
    "NoOfForms": "high_risk_when_high",
    "NoOfInputFields": "high_risk_when_high",
    "NoOfPasswordFields": "high_risk_when_high",
    "HasLoginForm": "high_risk_when_high",
    "HasExternalFormSubmit": "high_risk_when_high",
    "NoOfIFrames": "high_risk_when_high",
    "NoOfScripts": "high_risk_when_high",
    "NoOfExternalScripts": "high_risk_when_high",
    "NoOfExternalLinks": "high_risk_when_high",
    "RedirectCount": "high_risk_when_high",
    "HasMetaRefresh": "high_risk_when_high",
    "HasJavaScriptRedirect": "high_risk_when_high",
    "DomainTitleMatch": "high_risk_when_low",
    "TitleDomainTokenOverlap": "high_risk_when_low",
}


def build_feature_impacts(
    features: Mapping[str, float | int | bool | None],
    normalized_features: Mapping[str, float | int | bool | None],
    feature_importances: Mapping[str, float] | None = None,
    local_contributions: Mapping[str, float] | None = None,
) -> list[FeatureImpact]:
    if local_contributions:
        impacts = [
            FeatureImpact.from_value(feature, features.get(feature), impact)
            for feature, impact in local_contributions.items()
            if feature in features
        ]
        impacts.sort(key=lambda item: abs(item.impact), reverse=True)
        return impacts

    impacts: list[FeatureImpact] = []
    importance_lookup = dict(feature_importances or {})
    for feature, raw_value in features.items():
        if feature not in RISK_ORIENTATION:
            continue
        if importance_lookup and feature not in importance_lookup:
            continue
        normalized = normalized_features.get(feature)
        if not isinstance(normalized, (int, float, bool)):
            continue
        normalized_value = float(normalized)
        centered = normalized_value - 0.5
        if RISK_ORIENTATION[feature] == "high_risk_when_low":
            centered = 0.5 - normalized_value
        weight = float(importance_lookup.get(feature, 1.0))
        impact = centered * 2.0 * max(weight, 0.05)
        impacts.append(FeatureImpact.from_value(feature, raw_value, impact))
    impacts.sort(key=lambda item: abs(item.impact), reverse=True)
    return impacts
