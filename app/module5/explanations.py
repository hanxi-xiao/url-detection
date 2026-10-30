"""Rank model impacts and convert them into understandable explanations."""

from __future__ import annotations

from time import perf_counter
from typing import Iterable

from .feature_catalog import translate_feature_impact
from .models import ExplainabilityResult, ExplanationDirection, FeatureImpact, PredictionContext, RiskCategory, TechnicalReason
from .recommendations import generate_recommendations


class ExplanationService:
    def __init__(self, *, max_reasons: int = 3, minimum_absolute_impact: float = 1e-9) -> None:
        if max_reasons < 1:
            raise ValueError("max_reasons must be at least 1")
        if minimum_absolute_impact < 0:
            raise ValueError("minimum_absolute_impact cannot be negative")
        self.max_reasons = max_reasons
        self.minimum_absolute_impact = minimum_absolute_impact

    def explain(self, context: PredictionContext, impacts: Iterable[FeatureImpact]) -> ExplainabilityResult:
        started_at = perf_counter()
        preferred_direction = (
            ExplanationDirection.DECREASES_RISK
            if context.risk_category is RiskCategory.SAFE
            else ExplanationDirection.INCREASES_RISK
        )
        contextual_reasons = self._contextual_reasons(context)
        eligible: list[FeatureImpact] = []
        for impact in impacts:
            if impact.feature not in context.features:
                continue
            if abs(impact.impact) < self.minimum_absolute_impact:
                continue
            if not self._is_displayable_impact(impact):
                continue
            eligible.append(
                FeatureImpact(
                    feature=impact.feature,
                    value=context.features[impact.feature],
                    impact=impact.impact,
                    direction=impact.direction,
                )
            )

        eligible = [item for item in eligible if item.direction is preferred_direction]
        eligible.sort(key=lambda item: (-abs(item.impact), item.feature))
        reasons: list[TechnicalReason] = list(contextual_reasons)
        for impact in eligible:
            translated = translate_feature_impact(
                impact,
                context.evidence.get("domainIdentity")
                if isinstance(context.evidence.get("domainIdentity"), dict)
                else None,
            )
            if translated is None:
                continue
            if any(reason.title == translated.title for reason in reasons):
                continue
            reasons.append(translated)
            if len(reasons) == self.max_reasons:
                break
        if not reasons:
            reasons.append(self._fallback_reason(context))
        elapsed_ms = (perf_counter() - started_at) * 1000.0
        return ExplainabilityResult(
            request_id=context.request_id,
            model_version=context.model_version,
            reasons=tuple(reasons),
            recommendations=generate_recommendations(context.risk_category),
            explanation_ms=elapsed_ms,
        )

    @staticmethod
    def _contextual_reasons(context: PredictionContext) -> list[TechnicalReason]:
        reasons: list[TechnicalReason] = []
        policy_override = context.evidence.get("policyOverride")
        if isinstance(policy_override, dict) and policy_override.get("listType") in {"allowlist", "blocklist"}:
            is_allowlist = policy_override["listType"] == "allowlist"
            expires_at = policy_override.get("expiresAt")
            reasons.append(
                TechnicalReason(
                    feature="PolicyOverrideMatched",
                    value=1.0,
                    impact=-1.0 if is_allowlist else 1.0,
                    direction=(
                        ExplanationDirection.DECREASES_RISK
                        if is_allowlist
                        else ExplanationDirection.INCREASES_RISK
                    ),
                    title="Admin-reviewed list decision applied",
                    detail=(
                        "This URL matched an administrator-reviewed allowlist entry, so the stored decision was used directly."
                        if is_allowlist
                        else "This URL matched an administrator-reviewed blocklist entry, so the stored decision was used directly."
                    )
                    + (
                        f" The temporary allowlist entry expires at {expires_at}."
                        if is_allowlist and expires_at
                        else ""
                    ),
                )
            )
        identity = context.evidence.get("domainIdentity")
        if isinstance(identity, dict) and identity.get("isKnownOfficialDomain"):
            reasons.append(
                TechnicalReason(
                    feature="IsKnownOfficialDomain",
                    value=1.0,
                    impact=-0.8,
                    direction=ExplanationDirection.DECREASES_RISK,
                    title="Recognised official domain",
                    detail=(
                        f"The registrable domain {identity.get('registrableDomain')} "
                        "matches the configured official-domain list."
                    ),
                )
            )
        elif isinstance(identity, dict) and identity.get("isKnownOfficialSubdomain"):
            reasons.append(
                TechnicalReason(
                    feature="IsKnownOfficialSubdomain",
                    value=1.0,
                    impact=-0.8,
                    direction=ExplanationDirection.DECREASES_RISK,
                    title="Recognised official subdomain",
                    detail=(
                        f"The hostname uses a configured official service under "
                        f"{identity.get('registrableDomain')}."
                    ),
                )
            )
        if isinstance(identity, dict) and identity.get("impersonatedDomain"):
            brand = identity.get("impersonatedBrand")
            target = identity["impersonatedDomain"]
            if identity.get("brandInDeceptivePosition"):
                detail = (
                    f"The effective registrable domain is "
                    f"{identity.get('effectiveRegistrableDomain')}, while "
                    f"{brand or 'a monitored brand'} appears elsewhere in the hostname."
                )
            else:
                detail = (
                    f"The domain closely resembles {target}"
                    f"{f' ({brand})' if brand else ''}, which can indicate a typosquatting attempt."
                )
            reasons.append(
                TechnicalReason(
                    feature="HasBrandImpersonation",
                    value=context.features.get("HasBrandImpersonation", 1.0),
                    impact=max(float(context.features.get("BrandSimilarityScore", 0.0)), 0.8),
                    direction=ExplanationDirection.INCREASES_RISK,
                    title="Possible brand impersonation",
                    detail=detail,
                )
            )

        if isinstance(identity, dict) and identity.get("hasAtSymbol"):
            reasons.append(
                TechnicalReason(
                    feature="HasAtSymbol",
                    value=1.0,
                    impact=0.9,
                    direction=ExplanationDirection.INCREASES_RISK,
                    title="Destination hidden after @ symbol",
                    detail=(
                        f"The effective destination is "
                        f"{identity.get('effectiveRegistrableDomain')}, not the text before @."
                    ),
                )
            )
        if isinstance(identity, dict) and identity.get("isShorteningService"):
            reasons.append(
                TechnicalReason(
                    feature="IsShorteningService",
                    value=1.0,
                    impact=0.5,
                    direction=ExplanationDirection.INCREASES_RISK,
                    title="Shortened URL destination hidden",
                    detail="The final destination must be inspected through the redirect chain before the link can be verified.",
                )
            )

        web_evidence = context.evidence.get("webEvidence")
        if isinstance(web_evidence, dict) and not web_evidence.get("available", False):
            reasons.append(
                TechnicalReason(
                    feature="HTMLAvailable",
                    value=0.0,
                    impact=0.0,
                    direction=ExplanationDirection.INCREASES_RISK,
                    title="Webpage evidence unavailable",
                    detail=(
                        "The server could not retrieve complete webpage content. "
                        "This limits the analysis but does not by itself prove that the URL is phishing."
                    ),
                )
            )
        return reasons[:2]

    @staticmethod
    def _is_displayable_impact(impact: FeatureImpact) -> bool:
        """Avoid user-facing wording that contradicts the observed feature value."""
        if impact.direction is not ExplanationDirection.INCREASES_RISK:
            try:
                value = float(impact.value)
            except (TypeError, ValueError):
                return False
            low_signal_safe_absences = {
                "HasBrandImpersonation",
                "HasSuspiciousPattern",
                "HasMetaRefresh",
                "HasJavaScriptRedirect",
                "HasExternalFormSubmit",
                "HasLoginForm",
                "NoOfPasswordFields",
            }
            if impact.feature in low_signal_safe_absences and value <= 0.0:
                return False
            return True
        try:
            value = float(impact.value)
        except (TypeError, ValueError):
            return False

        minimums = {
            "URLLength": 60.0,
            "DomainLength": 25.0,
            "NoOfSpecialCharsInURL": 8.0,
            "NoOfSubDomain": 2.0,
            "SuspiciousPatternCount": 1.0,
            "NoOfPasswordFields": 1.0,
            "NoOfIFrames": 1.0,
            "RedirectCount": 1.0,
            "NoOfForms": 1.0,
            "NoOfInputFields": 3.0,
            "NoOfScripts": 20.0,
            "NoOfExternalScripts": 1.0,
            "NoOfExternalLinks": 3.0,
            "HTMLLength": 1_000_000.0,
            "TitleLength": 120.0,
            "BrandSimilarityScore": 0.80,
        }
        binary_risk_features = {
            "IsDomainIP",
            "HasSuspiciousPattern",
            "HasBrandImpersonation",
            "HasLoginForm",
            "HasExternalFormSubmit",
            "HasMetaRefresh",
            "HasJavaScriptRedirect",
        }
        low_value_risk_features = {
            "UsesHTTPS",
            "HTMLAvailable",
            "HasTitle",
            "DomainTitleMatch",
            "TitleDomainTokenOverlap",
        }

        if impact.feature in binary_risk_features:
            return value >= 1.0
        if impact.feature in low_value_risk_features:
            return value < 0.5
        return value >= minimums.get(impact.feature, 0.0)

    @staticmethod
    def _fallback_reason(context: PredictionContext) -> TechnicalReason:
        if context.risk_category is RiskCategory.SAFE:
            direction = ExplanationDirection.DECREASES_RISK
            title = "Overall model assessment"
            detail = "No single available feature dominated this lower-risk result. Continue with normal caution."
        else:
            direction = ExplanationDirection.INCREASES_RISK
            title = "Combined risk indicators"
            detail = "Several smaller indicators contributed to this result, but no single factor was strong enough to display on its own."
        return TechnicalReason(
            feature="model_assessment",
            value=None,
            impact=0.0,
            direction=direction,
            title=title,
            detail=detail,
        )
