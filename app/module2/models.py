from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class PreprocessedSubmission:
    request_id: str
    raw_url: str
    normalized_url: str
    domain: str
    scheme: str
    html: str | None = None
    final_url: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    fetch_status: str = "not_attempted"

    def to_feature_input(self) -> dict[str, Any]:
        return {
            "requestId": self.request_id,
            "rawUrl": self.raw_url,
            "normalizedUrl": self.normalized_url,
            "html": self.html,
            "finalUrl": self.final_url,
            "redirectChain": self.redirect_chain,
            "fetchStatus": self.fetch_status,
        }

    def to_api_dict(self) -> dict[str, Any]:
        return {
            "requestId": self.request_id,
            "rawUrl": self.raw_url,
            "normalizedUrl": self.normalized_url,
            "domain": self.domain,
            "scheme": self.scheme,
            "finalUrl": self.final_url,
            "redirectChain": self.redirect_chain,
            "warnings": self.warnings,
            "fetchStatus": self.fetch_status,
        }
