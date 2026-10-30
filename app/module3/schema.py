"""Stable feature schema for Module 3."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

FEATURE_SCHEMA_VERSION: Final[str] = "clearurl-m3-v3"


@dataclass(frozen=True, slots=True)
class FeatureDefinition:
    name: str
    default: float
    minimum: float
    maximum: float
    binary: bool = False


FEATURE_DEFINITIONS: Final[tuple[FeatureDefinition, ...]] = (
    FeatureDefinition("URLLength", 0.0, 0.0, 2_000.0),
    FeatureDefinition("DomainLength", 0.0, 0.0, 253.0),
    FeatureDefinition("NoOfSpecialCharsInURL", 0.0, 0.0, 200.0),
    FeatureDefinition("IsDomainIP", 0.0, 0.0, 1.0, binary=True),
    FeatureDefinition("NoOfSubDomain", 0.0, 0.0, 10.0),
    FeatureDefinition("HasSuspiciousPattern", 0.0, 0.0, 1.0, binary=True),
    FeatureDefinition("SuspiciousPatternCount", 0.0, 0.0, 20.0),
    FeatureDefinition("BrandSimilarityScore", 0.0, 0.0, 1.0),
    FeatureDefinition("HasBrandImpersonation", 0.0, 0.0, 1.0, binary=True),
    FeatureDefinition("IsKnownOfficialDomain", 0.0, 0.0, 1.0, binary=True),
    FeatureDefinition("IsKnownOfficialSubdomain", 0.0, 0.0, 1.0, binary=True),
    FeatureDefinition("BrandInDeceptivePosition", 0.0, 0.0, 1.0, binary=True),
    FeatureDefinition("HasAtSymbol", 0.0, 0.0, 1.0, binary=True),
    FeatureDefinition("IsShorteningService", 0.0, 0.0, 1.0, binary=True),
    FeatureDefinition("HasSensitiveKeyword", 0.0, 0.0, 1.0, binary=True),
    FeatureDefinition("SensitiveKeywordCount", 0.0, 0.0, 30.0),
    FeatureDefinition("HasLongSensitivePath", 0.0, 0.0, 1.0, binary=True),
    FeatureDefinition("UsesHTTPS", 0.0, 0.0, 1.0, binary=True),
    FeatureDefinition("HTMLAvailable", 0.0, 0.0, 1.0, binary=True),
    FeatureDefinition("HasTitle", 0.0, 0.0, 1.0, binary=True),
    FeatureDefinition("TitleLength", 0.0, 0.0, 300.0),
    FeatureDefinition("HTMLLength", 0.0, 0.0, 2_000_000.0),
    FeatureDefinition("NoOfForms", 0.0, 0.0, 30.0),
    FeatureDefinition("NoOfInputFields", 0.0, 0.0, 200.0),
    FeatureDefinition("NoOfPasswordFields", 0.0, 0.0, 20.0),
    FeatureDefinition("HasLoginForm", 0.0, 0.0, 1.0, binary=True),
    FeatureDefinition("HasExternalFormSubmit", 0.0, 0.0, 1.0, binary=True),
    FeatureDefinition("NoOfIFrames", 0.0, 0.0, 30.0),
    FeatureDefinition("NoOfScripts", 0.0, 0.0, 200.0),
    FeatureDefinition("NoOfExternalScripts", 0.0, 0.0, 100.0),
    FeatureDefinition("NoOfExternalLinks", 0.0, 0.0, 500.0),
    FeatureDefinition("RedirectCount", 0.0, 0.0, 20.0),
    FeatureDefinition("HasMetaRefresh", 0.0, 0.0, 1.0, binary=True),
    FeatureDefinition("HasJavaScriptRedirect", 0.0, 0.0, 1.0, binary=True),
    FeatureDefinition("DomainTitleMatch", 0.5, 0.0, 1.0),
    FeatureDefinition("TitleDomainTokenOverlap", 0.5, 0.0, 1.0),
)

FEATURE_ORDER: Final[tuple[str, ...]] = tuple(
    definition.name for definition in FEATURE_DEFINITIONS
)
FEATURE_BY_NAME: Final[dict[str, FeatureDefinition]] = {
    definition.name: definition for definition in FEATURE_DEFINITIONS
}
