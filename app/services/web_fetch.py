from __future__ import annotations

from dataclasses import dataclass, replace
from socket import timeout as SocketTimeout
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from app.module2.models import PreprocessedSubmission


DEFAULT_USER_AGENT = "ClearURLBot/1.0 (+https://clearurl.local)"


@dataclass(slots=True)
class WebFetchResult:
    html: str | None
    final_url: str | None
    redirect_chain: list[str]
    warnings: list[str]
    fetch_status: str


class TrackingRedirectHandler(HTTPRedirectHandler):
    def __init__(self, *, max_redirects: int = 10) -> None:
        super().__init__()
        self.max_redirects = max_redirects
        self.redirect_chain: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        if len(self.redirect_chain) >= self.max_redirects:
            raise HTTPError(newurl, code, "Maximum redirect limit reached.", headers, fp)
        self.redirect_chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_web_content(
    url: str,
    *,
    timeout_seconds: float = 8.0,
    max_bytes: int = 1_500_000,
) -> WebFetchResult:
    handler = TrackingRedirectHandler()
    opener = build_opener(handler)
    request = Request(
        url,
        headers={
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
        },
    )

    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            final_url = response.geturl()
            content_type = response.headers.get_content_type()
            charset = response.headers.get_content_charset() or "utf-8"
            warnings: list[str] = []
            raw_body = response.read(max_bytes + 1)
            if len(raw_body) > max_bytes:
                raw_body = raw_body[:max_bytes]
                warnings.append("Fetched webpage content was truncated to the maximum allowed size.")
            if not content_type.startswith("text/html"):
                warnings.append(f"Fetched content type was {content_type}, so webpage HTML features were skipped.")
                return WebFetchResult(
                    html=None,
                    final_url=final_url,
                    redirect_chain=list(handler.redirect_chain),
                    warnings=warnings,
                    fetch_status="unsupported_content",
                )
            html = raw_body.decode(charset, errors="replace")
            return WebFetchResult(
                html=html,
                final_url=final_url,
                redirect_chain=list(handler.redirect_chain),
                warnings=warnings,
                fetch_status="success",
            )
    except HTTPError as error:
        return WebFetchResult(
            html=None,
            final_url=error.geturl() if hasattr(error, "geturl") else None,
            redirect_chain=list(handler.redirect_chain),
            warnings=[f"Automatic webpage fetch failed with HTTP status {error.code}."],
            fetch_status="http_error",
        )
    except (URLError, SocketTimeout, TimeoutError):
        return WebFetchResult(
            html=None,
            final_url=None,
            redirect_chain=list(handler.redirect_chain),
            warnings=["Automatic webpage fetch failed before HTML could be collected."],
            fetch_status="network_error",
        )


def enrich_submission_with_web_content(submission: PreprocessedSubmission) -> PreprocessedSubmission:
    if submission.html is not None:
        return submission
    if urlsplit(submission.normalized_url).scheme not in {"http", "https"}:
        return submission

    fetched = fetch_web_content(submission.normalized_url)
    warnings = [*submission.warnings, *fetched.warnings]
    final_url = fetched.final_url or submission.final_url
    redirect_chain = fetched.redirect_chain or submission.redirect_chain

    return replace(
        submission,
        html=fetched.html,
        final_url=final_url,
        redirect_chain=redirect_chain,
        warnings=warnings,
        fetch_status=fetched.fetch_status,
    )
