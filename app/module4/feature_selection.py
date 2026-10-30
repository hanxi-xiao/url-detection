from __future__ import annotations

from typing import Final


MODEL_FEATURES: Final[tuple[str, ...]] = (
    "URLLength",
    "DomainLength",
    "NoOfSpecialCharsInURL",
    "IsDomainIP",
    "NoOfSubDomain",
    "HasSuspiciousPattern",
    "SuspiciousPatternCount",
    "BrandSimilarityScore",
    "HasBrandImpersonation",
    "IsKnownOfficialDomain",
    "IsKnownOfficialSubdomain",
    "BrandInDeceptivePosition",
    "HasAtSymbol",
    "IsShorteningService",
    "HasSensitiveKeyword",
    "SensitiveKeywordCount",
    "HasLongSensitivePath",
    "UsesHTTPS",
    "NoOfPasswordFields",
    "HasLoginForm",
    "HasExternalFormSubmit",
    "NoOfIFrames",
    "DomainTitleMatch",
    "TitleDomainTokenOverlap",
)
