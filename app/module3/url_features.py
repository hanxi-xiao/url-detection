from __future__ import annotations

import ipaddress
import re
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import unquote, urlsplit

SUSPICIOUS_KEYWORDS = (
    "account",
    "auth",
    "banking",
    "bonus",
    "confirm",
    "credential",
    "crypto",
    "free",
    "giveaway",
    "invoice",
    "login",
    "password",
    "payment",
    "recover",
    "secure",
    "signin",
    "support",
    "unlock",
    "update",
    "urgent",
    "verify",
    "wallet",
    "webscr",
)

KNOWN_BRAND_DOMAINS: dict[str, str] = {
    "alipay.com": "Alipay",
    "amazon.com": "Amazon",
    "apple.com": "Apple",
    "baidu.com": "Baidu",
    "bilibili.com": "Bilibili",
    "facebook.com": "Facebook",
    "github.com": "GitHub",
    "gitlab.com": "GitLab",
    "google.com": "Google",
    "douyin.com": "Douyin",
    "gov.cn": "Chinese Government",
    "huawei.com": "Huawei",
    "jd.com": "JD.com",
    "mi.com": "Xiaomi",
    "microsoft.com": "Microsoft",
    "microsoftonline.com": "Microsoft",
    "monash.edu": "Monash University",
    "paypal.com": "PayPal",
    "qq.com": "QQ",
    "sina.com.cn": "Sina",
    "taobao.com": "Taobao",
    "youtube.com": "YouTube",
    "163.com": "NetEase",
    "weibo.com": "Weibo",
    "zhihu.com": "Zhihu",
}

DIGIT_TO_LETTER = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})
SHORTENING_DOMAINS = {
    "bit.ly",
    "cutt.ly",
    "is.gd",
    "lnkd.in",
    "ow.ly",
    "rb.gy",
    "t.co",
    "tinyurl.com",
    "urlzs.com",
}
OFFICIAL_SUBDOMAIN_LABELS: dict[str, set[str]] = {
    "apple.com": {"appleid", "www"},
    "amazon.com": {"www"},
    "baidu.com": {"fanyi", "www"},
    "douyin.com": {"www"},
    "gov.cn": {"www"},
    "huawei.com": {"www"},
    "jd.com": {"www", "passport"},
    "mi.com": {"www", "account"},
    "github.com": {"github", "www"},
    "microsoft.com": {"www"},
    "microsoftonline.com": {"login", "www"},
    "monash.edu": {
        "www",
        "my",
        "moodle",
        "learning",
        "lms",
        "library",
        "students",
        "staff",
        "auth",
        "login",
        "git",
        "infotech",
    },
    "paypal.com": {"www"},
    "sina.com.cn": {"www"},
    "youtube.com": {"www"},
    "163.com": {"www"},
    "weibo.com": {"www", "login"},
    "zhihu.com": {"www", "passport"},
    "gitlab.com": {"about", "docs", "gitlab", "www"},
    "google.com": {
        "accounts",
        "calendar",
        "classroom",
        "docs",
        "drive",
        "forms",
        "mail",
        "meet",
        "myaccount",
        "sheets",
        "sites",
        "slides",
        "support",
        "www",
    },
}

SECOND_LEVEL_SUFFIXES = {
    "ac.uk",
    "co.jp",
    "co.nz",
    "co.uk",
    "com.au",
    "com.cn",
    "com.hk",
    "com.sg",
    "edu.au",
    "gov.cn",
    "gov.uk",
    "net.au",
    "org.au",
    "org.uk",
}


def is_ip_address(hostname: str) -> bool:
    candidate = hostname.strip("[]")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def count_subdomains(hostname: str) -> int:
    if not hostname or is_ip_address(hostname):
        return 0
    labels = [label for label in hostname.lower().strip(".").split(".") if label]
    if len(labels) <= 2:
        return 0
    second_level_suffixes = {
        "ac.uk",
        "co.jp",
        "co.nz",
        "co.uk",
        "com.au",
        "com.cn",
        "com.hk",
        "com.sg",
        "edu.au",
        "gov.uk",
        "net.au",
        "org.au",
        "org.uk",
    }
    suffix = ".".join(labels[-2:])
    registrable_labels = 3 if suffix in second_level_suffixes else 2
    return max(len(labels) - registrable_labels, 0)


def count_suspicious_patterns(url: str, hostname: str) -> int:
    decoded = unquote(url).lower()
    count = sum(1 for keyword in SUSPICIOUS_KEYWORDS if keyword in decoded)
    structural_patterns = (
        "@" in url,
        hostname.startswith("xn--") or ".xn--" in hostname,
        hostname.count("-") >= 3,
        "//" in urlsplit(url).path,
        bool(re.search(r"%[0-9a-fA-F]{2}", url)),
    )
    count += sum(structural_patterns)
    return count


def registrable_domain(hostname: str) -> str:
    hostname = hostname.lower().strip(".")
    if hostname in {"gov.cn", "www.gov.cn"}:
        return "gov.cn"
    labels = [label for label in hostname.split(".") if label]
    if len(labels) < 2:
        return hostname.lower().strip(".")
    suffix = ".".join(labels[-2:])
    if suffix in SECOND_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def extract_domain_identity_features(
    normalized_url: str,
    raw_url: str | None = None,
) -> tuple[dict[str, float], dict[str, Any]]:
    hostname = (urlsplit(normalized_url).hostname or "").lower().rstrip(".")
    lexical_url = (raw_url or normalized_url).strip()
    domain = registrable_domain(hostname)
    label = domain.split(".")[0] if domain else ""
    all_labels = [part for part in hostname.split(".") if part]
    subdomain_labels = set(all_labels[:-2]) if len(all_labels) > 2 else set()
    translated_label = label.translate(DIGIT_TO_LETTER)
    digit_substitutions = [
        {
            "position": index,
            "observed": character,
            "expected": character.translate(DIGIT_TO_LETTER),
        }
        for index, character in enumerate(label)
        if character in "013457"
    ]
    best_similarity = 0.0
    best_brand_domain: str | None = None
    best_brand_name: str | None = None

    for brand_domain, brand_name in KNOWN_BRAND_DOMAINS.items():
        brand_label = brand_domain.split(".")[0]
        similarity = SequenceMatcher(None, translated_label, brand_label).ratio()
        if domain == brand_domain:
            similarity = 0.0
        if similarity > best_similarity:
            best_similarity = similarity
            best_brand_domain = brand_domain
            best_brand_name = brand_name

    official_domain = domain in KNOWN_BRAND_DOMAINS
    official_subdomain = bool(
        official_domain
        and subdomain_labels.intersection(OFFICIAL_SUBDOMAIN_LABELS.get(domain, set()))
    )
    hostname_as_text = hostname.replace(".", "-")
    deceptive_brand_domain = next(
        (
            brand_domain
            for brand_domain in KNOWN_BRAND_DOMAINS
            if len(brand_domain.split(".")[0]) >= 4
            and brand_domain.split(".")[0] in hostname_as_text
        ),
        None,
    )
    brand_in_hostname = deceptive_brand_domain is not None
    brand_in_deceptive_position = bool(
        brand_in_hostname and not official_domain and not official_subdomain
    )
    if brand_in_deceptive_position and deceptive_brand_domain:
        best_brand_domain = deceptive_brand_domain
        best_brand_name = KNOWN_BRAND_DOMAINS[deceptive_brand_domain]
    is_typosquat = bool(best_brand_domain and best_similarity >= 0.80 and domain != best_brand_domain)
    is_impersonation = is_typosquat or brand_in_deceptive_position
    has_digit_substitution = bool(
        is_impersonation
        and digit_substitutions
        and translated_label != label
    )
    impersonation_techniques: list[str] = []
    if is_typosquat:
        impersonation_techniques.append("lookalike_domain")
    if has_digit_substitution:
        impersonation_techniques.append("digit_letter_substitution")
    if brand_in_deceptive_position:
        impersonation_techniques.append("brand_in_deceptive_position")
    if "@" in lexical_url:
        impersonation_techniques.append("at_symbol_destination_obfuscation")
    return (
        {
            "BrandSimilarityScore": float(best_similarity if is_impersonation else 0.0),
            "HasBrandImpersonation": float(is_impersonation),
            "IsKnownOfficialDomain": float(official_domain),
            "IsKnownOfficialSubdomain": float(official_subdomain),
            "BrandInDeceptivePosition": float(brand_in_deceptive_position),
            "HasAtSymbol": float("@" in lexical_url),
            "IsShorteningService": float(domain in SHORTENING_DOMAINS),
            "HasSensitiveKeyword": float(any(keyword in lexical_url.lower() for keyword in SUSPICIOUS_KEYWORDS)),
            "SensitiveKeywordCount": float(count_suspicious_patterns(lexical_url, hostname)),
            "HasLongSensitivePath": float(
                len(urlsplit(lexical_url).path) >= 45
                and sum(keyword in urlsplit(lexical_url).path.lower() for keyword in SUSPICIOUS_KEYWORDS) >= 2
            ),
        },
        {
            "registrableDomain": domain,
            "impersonatedBrand": best_brand_name if is_impersonation else None,
            "impersonatedDomain": best_brand_domain if is_impersonation else None,
            "hasDigitLetterSubstitution": has_digit_substitution,
            "digitLetterSubstitutions": digit_substitutions if has_digit_substitution else [],
            "impersonationTechniques": impersonation_techniques,
            "isKnownOfficialDomain": official_domain,
            "isKnownOfficialSubdomain": official_subdomain,
            "brandInDeceptivePosition": brand_in_deceptive_position,
            "effectiveRegistrableDomain": domain,
            "isShorteningService": domain in SHORTENING_DOMAINS,
            "hasAtSymbol": "@" in lexical_url,
        },
    )


def extract_url_features(normalized_url: str, raw_url: str | None = None) -> dict[str, float]:
    parsed = urlsplit(normalized_url)
    lexical_url = (raw_url or normalized_url).strip()
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("normalized URL must use http or https")
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise ValueError("normalized URL must contain a hostname")

    suspicious_count = count_suspicious_patterns(lexical_url, hostname)
    special_count = sum(1 for char in lexical_url if not char.isalnum())

    return {
        "URLLength": float(len(lexical_url)),
        "DomainLength": float(len(hostname)),
        "NoOfSpecialCharsInURL": float(special_count),
        "IsDomainIP": float(is_ip_address(hostname)),
        "NoOfSubDomain": float(count_subdomains(hostname)),
        "HasSuspiciousPattern": float(suspicious_count > 0),
        "SuspiciousPatternCount": float(suspicious_count),
        "UsesHTTPS": float(parsed.scheme.lower() == "https"),
    }
