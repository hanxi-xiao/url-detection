from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.module3.url_features import count_suspicious_patterns
from app.module4.feature_selection import MODEL_FEATURES


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert PhiUSIIL into the Module 4 training schema."
    )
    parser.add_argument("--input", required=True, type=Path, help="PhiUSIIL CSV path")
    parser.add_argument("--output", required=True, type=Path, help="Output CSV path")
    return parser


def safe_string(value: object) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    return str(value)


def derive_suspicious_features(frame: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
    counts = []
    for _, row in frame.iterrows():
        url = safe_string(row.get("URL"))
        hostname = (urlsplit(url).hostname or safe_string(row.get("Domain"))).lower()
        keyword_hits = count_suspicious_patterns(url, hostname)
        extra_hits = int(float(row.get("HasObfuscation", 0) or 0) > 0) + int(float(row.get("Bank", 0) or 0) > 0) + int(float(row.get("Pay", 0) or 0) > 0) + int(float(row.get("Crypto", 0) or 0) > 0)
        count = keyword_hits + extra_hits
        counts.append(count)
    count_series = pd.Series(counts, index=frame.index, dtype=float)
    return (count_series > 0).astype(float), count_series


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    frame = pd.read_csv(args.input)
    required = {
        "URL",
        "URLLength",
        "DomainLength",
        "IsDomainIP",
        "NoOfSubDomain",
        "NoOfEqualsInURL",
        "NoOfQMarkInURL",
        "NoOfAmpersandInURL",
        "NoOfOtherSpecialCharsInURL",
        "IsHTTPS",
        "HasTitle",
        "Title",
        "DomainTitleMatchScore",
        "NoOfURLRedirect",
        "NoOfSelfRedirect",
        "HasExternalFormSubmit",
        "NoOfiFrame",
        "NoOfJS",
        "NoOfExternalRef",
        "HasPasswordField",
        "label",
    }
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError("PhiUSIIL CSV is missing required columns: " + ", ".join(missing))

    has_suspicious_pattern, suspicious_pattern_count = derive_suspicious_features(frame)
    title_text = frame["Title"].map(safe_string)
    prepared = pd.DataFrame(
        {
            "URLLength": pd.to_numeric(frame["URLLength"], errors="coerce"),
            "DomainLength": pd.to_numeric(frame["DomainLength"], errors="coerce"),
            "NoOfSpecialCharsInURL": (
                pd.to_numeric(frame["NoOfEqualsInURL"], errors="coerce").fillna(0)
                + pd.to_numeric(frame["NoOfQMarkInURL"], errors="coerce").fillna(0)
                + pd.to_numeric(frame["NoOfAmpersandInURL"], errors="coerce").fillna(0)
                + pd.to_numeric(frame["NoOfOtherSpecialCharsInURL"], errors="coerce").fillna(0)
            ),
            "IsDomainIP": pd.to_numeric(frame["IsDomainIP"], errors="coerce"),
            "NoOfSubDomain": pd.to_numeric(frame["NoOfSubDomain"], errors="coerce"),
            "HasSuspiciousPattern": has_suspicious_pattern,
            "SuspiciousPatternCount": suspicious_pattern_count,
            "UsesHTTPS": pd.to_numeric(frame["IsHTTPS"], errors="coerce"),
            "HasTitle": pd.to_numeric(frame["HasTitle"], errors="coerce"),
            "TitleLength": title_text.map(len).astype(float),
            "NoOfPasswordFields": pd.to_numeric(frame["HasPasswordField"], errors="coerce"),
            "HasLoginForm": (
                (pd.to_numeric(frame["HasPasswordField"], errors="coerce").fillna(0) > 0)
                | (pd.to_numeric(frame["HasExternalFormSubmit"], errors="coerce").fillna(0) > 0)
            ).astype(float),
            "HasExternalFormSubmit": pd.to_numeric(frame["HasExternalFormSubmit"], errors="coerce"),
            "NoOfIFrames": pd.to_numeric(frame["NoOfiFrame"], errors="coerce"),
            "NoOfScripts": pd.to_numeric(frame["NoOfJS"], errors="coerce"),
            "NoOfExternalLinks": pd.to_numeric(frame["NoOfExternalRef"], errors="coerce"),
            "RedirectCount": (
                pd.to_numeric(frame["NoOfURLRedirect"], errors="coerce").fillna(0)
                + pd.to_numeric(frame["NoOfSelfRedirect"], errors="coerce").fillna(0)
            ),
            "DomainTitleMatch": (
                pd.to_numeric(frame["DomainTitleMatchScore"], errors="coerce").fillna(0) >= 0.5
            ).astype(float),
            "TitleDomainTokenOverlap": pd.to_numeric(frame["DomainTitleMatchScore"], errors="coerce").clip(lower=0, upper=1),
        }
    )

    prepared["label"] = pd.to_numeric(frame["label"], errors="coerce").map({1: 0, 0: 1})
    if prepared["label"].isna().any():
        raise ValueError("Unsupported label values found. Expected PhiUSIIL 1=legitimate, 0=phishing.")
    prepared["label"] = prepared["label"].astype(int)
    prepared = prepared.loc[:, [*MODEL_FEATURES, "label"]]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    prepared.to_csv(args.output, index=False)
    print(f"Prepared {len(prepared)} rows")
    print(f"Saved to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
