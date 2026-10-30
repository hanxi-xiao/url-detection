from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import PreprocessedSubmission


@dataclass(slots=True)
class PreprocessingError(ValueError):
    code: str
    message: str

    def __str__(self) -> str:
        return self.message


def _normalize_url(raw_url: str) -> tuple[str, list[str]]:
    candidate = raw_url.strip()
    warnings: list[str] = []
    if not candidate:
        raise PreprocessingError("EMPTY_URL", "URL must not be empty.")

    if "://" not in candidate:
        candidate = f"https://{candidate}"
        warnings.append("No scheme supplied; defaulted to https://")

    parsed = urlsplit(candidate)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise PreprocessingError(
            "UNSUPPORTED_SCHEME",
            "Only http:// and https:// URLs are supported.",
        )

    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname or "." not in hostname and hostname != "localhost":
        raise PreprocessingError(
            "INVALID_HOST",
            "URL must contain a valid hostname or IP address.",
        )

    port = parsed.port
    include_port = port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    )
    netloc = hostname if not include_port else f"{hostname}:{port}"

    path = parsed.path or "/"
    while "//" in path:
        path = path.replace("//", "/")

    query_items = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)]
    normalized_query = urlencode(query_items, doseq=True)
    normalized = urlunsplit((scheme, netloc, path, normalized_query, ""))
    return normalized, warnings


def preprocess_submission(payload: dict[str, object]) -> PreprocessedSubmission:
    raw_url = payload.get("url")
    if not isinstance(raw_url, str):
        raise PreprocessingError("INVALID_URL", "Field `url` must be a string.")

    request_id = payload.get("requestId")
    if request_id is None:
        request_id = f"scan-{uuid4().hex}"
    elif not isinstance(request_id, str) or not request_id.strip():
        raise PreprocessingError("INVALID_REQUEST_ID", "Field `requestId` must be a non-empty string.")

    html = payload.get("html")
    if html is not None and not isinstance(html, str):
        raise PreprocessingError("INVALID_HTML", "Field `html` must be a string or null.")

    final_url = payload.get("finalUrl")
    if final_url is not None and not isinstance(final_url, str):
        raise PreprocessingError("INVALID_FINAL_URL", "Field `finalUrl` must be a string or null.")

    redirect_chain = payload.get("redirectChain", [])
    if not isinstance(redirect_chain, list) or not all(isinstance(item, str) for item in redirect_chain):
        raise PreprocessingError(
            "INVALID_REDIRECT_CHAIN",
            "Field `redirectChain` must be an array of strings.",
        )

    normalized_url, warnings = _normalize_url(raw_url)
    parsed = urlsplit(normalized_url)
    return PreprocessedSubmission(
        request_id=request_id,
        raw_url=raw_url,
        normalized_url=normalized_url,
        domain=parsed.hostname or "",
        scheme=parsed.scheme,
        html=html,
        final_url=final_url,
        redirect_chain=list(redirect_chain),
        warnings=warnings,
    )
