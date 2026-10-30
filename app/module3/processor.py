from __future__ import annotations

import math
from collections.abc import Mapping

from .models import FeatureQualityReport
from .schema import FEATURE_BY_NAME, FEATURE_DEFINITIONS, FEATURE_ORDER


class FeatureProcessor:
    def process(
        self, raw_features: Mapping[str, float | int | bool | None]
    ) -> tuple[dict[str, float], dict[str, float], list[float], FeatureQualityReport]:
        features: dict[str, float] = {}
        normalized: dict[str, float] = {}
        missing: list[str] = []
        imputed: list[str] = []
        out_of_range: list[str] = []
        warnings: list[str] = []

        for definition in FEATURE_DEFINITIONS:
            supplied = definition.name in raw_features
            value = raw_features.get(definition.name)

            if not supplied or value is None:
                missing.append(definition.name)
                imputed.append(definition.name)
                numeric_value = definition.default
            else:
                try:
                    numeric_value = float(value)
                except (TypeError, ValueError):
                    numeric_value = definition.default
                    imputed.append(definition.name)
                    warnings.append(f"{definition.name} was non-numeric and was imputed")

            if not math.isfinite(numeric_value):
                numeric_value = definition.default
                if definition.name not in imputed:
                    imputed.append(definition.name)
                warnings.append(f"{definition.name} was non-finite and was imputed")

            if definition.binary and numeric_value not in {0.0, 1.0}:
                out_of_range.append(definition.name)
                numeric_value = 1.0 if numeric_value > 0 else 0.0
            elif not definition.minimum <= numeric_value <= definition.maximum:
                out_of_range.append(definition.name)
                numeric_value = min(max(numeric_value, definition.minimum), definition.maximum)

            features[definition.name] = numeric_value
            if definition.binary:
                normalized_value = numeric_value
            elif definition.maximum == definition.minimum:
                normalized_value = 0.0
            else:
                normalized_value = (numeric_value - definition.minimum) / (
                    definition.maximum - definition.minimum
                )
            normalized[definition.name] = min(max(normalized_value, 0.0), 1.0)

        unknown_features = sorted(set(raw_features) - set(FEATURE_BY_NAME))
        if unknown_features:
            warnings.append("Ignored unknown features: " + ", ".join(unknown_features))

        feature_vector = [normalized[name] for name in FEATURE_ORDER]
        quality = FeatureQualityReport(
            is_valid=all(math.isfinite(value) and 0.0 <= value <= 1.0 for value in feature_vector),
            missing_features=missing,
            imputed_features=imputed,
            out_of_range_features=out_of_range,
            warnings=warnings,
        )
        return features, normalized, feature_vector, quality
