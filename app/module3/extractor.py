from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .models import FeatureExtractionResult, ProcessedURLData
from .processor import FeatureProcessor
from .schema import FEATURE_ORDER
from .url_features import extract_url_features, extract_domain_identity_features
from .webpage_features import extract_webpage_features


def extract_features(processed: ProcessedURLData | Mapping[str, Any]) -> FeatureExtractionResult:
    data = ProcessedURLData.from_mapping(processed) if isinstance(processed, Mapping) else processed
    if not isinstance(data, ProcessedURLData):
        raise TypeError("processed must be ProcessedURLData or a mapping")
    url_features = extract_url_features(data.normalized_url, data.raw_url)
    identity_features, identity_evidence = extract_domain_identity_features(
        data.normalized_url,
        data.raw_url,
    )
    webpage_features = extract_webpage_features(
        normalized_url=data.normalized_url,
        html=data.html,
        redirect_chain=data.redirect_chain,
        final_url=data.final_url,
    )
    combined = {**url_features, **identity_features, **webpage_features}
    features, normalized, vector, quality = FeatureProcessor().process(combined)
    return FeatureExtractionResult(
        request_id=data.request_id,
        normalized_url=data.normalized_url,
        features=features,
        normalized_features=normalized,
        feature_order=list(FEATURE_ORDER),
        feature_vector=vector,
        quality=quality,
        evidence={"domainIdentity": identity_evidence},
    )
