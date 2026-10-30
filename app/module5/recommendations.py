"""Deterministic, user-facing security recommendations."""

from __future__ import annotations

from .models import RiskCategory


RECOMMENDATIONS: dict[RiskCategory, tuple[str, ...]] = {
    RiskCategory.SAFE: (
        "Continue with normal caution.",
        "Check the domain before entering sensitive information.",
    ),
    RiskCategory.SUSPICIOUS: (
        "Do not enter passwords, payment details, or personal information.",
        "Verify the website through the organisation's official channel.",
        "Report the link if it was received unexpectedly.",
    ),
    RiskCategory.HIGH_RISK: (
        "Do not visit the website or enter any information.",
        "Close the page if it is already open.",
        "Report the link to your IT or security team.",
        "Contact IT promptly if credentials were already entered.",
    ),
}


def generate_recommendations(risk_category: RiskCategory | str) -> tuple[str, ...]:
    category = risk_category if isinstance(risk_category, RiskCategory) else RiskCategory(risk_category)
    return RECOMMENDATIONS[category]
