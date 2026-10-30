from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

LOGIN_TERMS = {
    "account",
    "auth",
    "credential",
    "email",
    "login",
    "password",
    "signin",
    "user",
    "username",
}


def normalize_attributes(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
    return {key.lower(): (value or "") for key, value in attrs}


def is_external(reference: str, base_url: str) -> bool:
    reference = reference.strip()
    if not reference or reference.startswith(("#", "javascript:", "mailto:", "tel:")):
        return False
    absolute = urljoin(base_url, reference)
    base_host = (urlsplit(base_url).hostname or "").lower().rstrip(".")
    target_host = (urlsplit(absolute).hostname or "").lower().rstrip(".")
    return bool(target_host and base_host and target_host != base_host)


class PageParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.in_title = False
        self.title_parts: list[str] = []
        self.form_actions: list[str] = []
        self.form_hints: list[str] = []
        self.input_hints: list[str] = []
        self.input_types: list[str] = []
        self.iframe_count = 0
        self.script_count = 0
        self.external_script_count = 0
        self.external_link_count = 0
        self.has_meta_refresh = False
        self.inline_script_parts: list[str] = []
        self.in_inline_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attributes = normalize_attributes(attrs)
        if tag == "title":
            self.in_title = True
            return
        if tag == "form":
            self.form_actions.append(attributes.get("action", ""))
            self.form_hints.append(
                " ".join(attributes.get(name, "") for name in ("id", "name", "class", "action")).lower()
            )
            return
        if tag == "input":
            input_type = attributes.get("type", "text").lower()
            self.input_types.append(input_type)
            self.input_hints.append(
                " ".join(
                    attributes.get(name, "")
                    for name in ("id", "name", "class", "placeholder", "autocomplete")
                ).lower()
            )
            return
        if tag == "iframe":
            self.iframe_count += 1
            return
        if tag == "script":
            self.script_count += 1
            source = attributes.get("src", "")
            if source:
                self.external_script_count += int(is_external(source, self.base_url))
                self.in_inline_script = False
            else:
                self.in_inline_script = True
            return
        if tag == "a":
            href = attributes.get("href", "")
            self.external_link_count += int(is_external(href, self.base_url))
            return
        if tag == "meta":
            if attributes.get("http-equiv", "").lower() == "refresh":
                self.has_meta_refresh = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False
        elif tag.lower() == "script":
            self.in_inline_script = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
        if self.in_inline_script:
            self.inline_script_parts.append(data)

    @property
    def title(self) -> str:
        return " ".join(" ".join(self.title_parts).split())

    @property
    def inline_javascript(self) -> str:
        return "\n".join(self.inline_script_parts)


def domain_tokens(url: str) -> set[str]:
    hostname = (urlsplit(url).hostname or "").lower().rstrip(".")
    if not hostname:
        return set()
    labels = hostname.split(".")
    if labels and labels[0] == "www":
        labels = labels[1:]
    if len(labels) >= 2:
        labels = labels[:-1]
    tokens: set[str] = set()
    for label in labels:
        for token in re.split(r"[^a-z0-9]+", label):
            if len(token) >= 3 and not token.isdigit():
                tokens.add(token)
    return tokens


def title_tokens(title: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9]+", title.lower())
        if len(token) >= 3 and not token.isdigit()
    }


def domain_title_consistency(url: str, title: str) -> tuple[float, float]:
    domain = domain_tokens(url)
    title_parts = title_tokens(title)
    if not domain or not title_parts:
        return 0.0, 0.0
    overlap = len(domain & title_parts) / len(domain)
    return float(overlap > 0), float(overlap)


def redirect_count(normalized_url: str, redirect_chain: list[str], final_url: str | None) -> int:
    if redirect_chain:
        first = redirect_chain[0].rstrip("/")
        original = normalized_url.rstrip("/")
        return max(len(redirect_chain) - int(first == original), 0)
    if final_url and final_url.rstrip("/") != normalized_url.rstrip("/"):
        return 1
    return 0


def extract_webpage_features(
    normalized_url: str,
    html: str | None,
    redirect_chain: list[str] | None = None,
    final_url: str | None = None,
) -> dict[str, float | None]:
    redirects = list(redirect_chain or [])
    redirects_found = float(redirect_count(normalized_url, redirects, final_url))
    if html is None:
        return {
            "HTMLAvailable": 0.0,
            "HasTitle": None,
            "TitleLength": None,
            "HTMLLength": None,
            "NoOfForms": None,
            "NoOfInputFields": None,
            "NoOfPasswordFields": None,
            "HasLoginForm": None,
            "HasExternalFormSubmit": None,
            "NoOfIFrames": None,
            "NoOfScripts": None,
            "NoOfExternalScripts": None,
            "NoOfExternalLinks": None,
            "RedirectCount": redirects_found,
            "HasMetaRefresh": None,
            "HasJavaScriptRedirect": None,
            "DomainTitleMatch": None,
            "TitleDomainTokenOverlap": None,
        }

    parser = PageParser(normalized_url)
    parser.feed(html)
    parser.close()

    password_fields = sum(input_type == "password" for input_type in parser.input_types)
    combined_hints = " ".join(parser.form_hints + parser.input_hints)
    has_login_terms = any(term in combined_hints for term in LOGIN_TERMS)
    has_login_form = bool(parser.form_actions) and (password_fields > 0 or has_login_terms)
    has_external_form_submit = any(is_external(action, normalized_url) for action in parser.form_actions)
    javascript_redirect_pattern = re.compile(
        r"(?:window\.)?location\s*(?:\.href)?\s*=|(?:window\.)?location\.(?:assign|replace)\s*\(",
        flags=re.IGNORECASE,
    )
    has_javascript_redirect = bool(javascript_redirect_pattern.search(parser.inline_javascript))
    title_match, title_overlap = domain_title_consistency(normalized_url, parser.title)

    return {
        "HTMLAvailable": 1.0,
        "HasTitle": float(bool(parser.title)),
        "TitleLength": float(len(parser.title)),
        "HTMLLength": float(len(html)),
        "NoOfForms": float(len(parser.form_actions)),
        "NoOfInputFields": float(len(parser.input_types)),
        "NoOfPasswordFields": float(password_fields),
        "HasLoginForm": float(has_login_form),
        "HasExternalFormSubmit": float(has_external_form_submit),
        "NoOfIFrames": float(parser.iframe_count),
        "NoOfScripts": float(parser.script_count),
        "NoOfExternalScripts": float(parser.external_script_count),
        "NoOfExternalLinks": float(parser.external_link_count),
        "RedirectCount": redirects_found,
        "HasMetaRefresh": float(parser.has_meta_refresh),
        "HasJavaScriptRedirect": float(has_javascript_redirect),
        "DomainTitleMatch": title_match,
        "TitleDomainTokenOverlap": title_overlap,
    }
