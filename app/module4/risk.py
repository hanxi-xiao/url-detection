from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RiskThresholds:
    suspicious: float = 0.45
    high_risk: float = 0.90

    def __post_init__(self) -> None:
        if not 0.0 <= self.suspicious < self.high_risk <= 1.0:
            raise ValueError("Thresholds must satisfy 0 <= suspicious < high_risk <= 1.")

    def to_dict(self) -> dict[str, float]:
        return {"suspicious": self.suspicious, "high_risk": self.high_risk}

    @classmethod
    def from_dict(cls, values: dict[str, float]) -> "RiskThresholds":
        return cls(
            suspicious=float(values["suspicious"]),
            high_risk=float(values["high_risk"]),
        )


def classify_risk(phishing_probability: float, thresholds: RiskThresholds | None = None) -> str:
    thresholds = thresholds or RiskThresholds()
    probability = float(phishing_probability)
    if not 0.0 <= probability <= 1.0:
        raise ValueError("Phishing probability must be between 0 and 1.")
    if probability >= thresholds.high_risk:
        return "High Risk"
    if probability >= thresholds.suspicious:
        return "Suspicious"
    return "Safe"
