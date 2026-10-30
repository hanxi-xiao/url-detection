from pathlib import Path
from uuid import uuid4

from app.module3 import extract_features
from app.module2.models import PreprocessedSubmission
from app.services.pipeline import analyze_submission
from app.services.state import feedback_repository, m5_service
from app.services.web_fetch import WebFetchResult, enrich_submission_with_web_content


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_feature_extraction_without_html_is_still_valid() -> None:
    result = extract_features(
        {
            "requestId": "scan-test-001",
            "normalizedUrl": "https://portal.example.com/login",
        }
    )
    assert result.quality.is_valid
    assert result.features["HTMLAvailable"] == 0.0


def test_feature_extraction_detects_brand_impersonation() -> None:
    result = extract_features(
        {
            "requestId": "scan-brand-001",
            "normalizedUrl": "https://go0gle.com/",
        }
    )
    assert result.features["HasBrandImpersonation"] == 1.0
    assert result.features["BrandSimilarityScore"] >= 0.8
    assert result.evidence["domainIdentity"]["impersonatedDomain"] == "google.com"


def test_feature_extraction_distinguishes_official_and_deceptive_domains() -> None:
    official = extract_features(
        {
            "requestId": "scan-official-domain",
            "normalizedUrl": "https://accounts.google.com",
        }
    )
    deceptive = extract_features(
        {
            "requestId": "scan-deceptive-domain",
            "normalizedUrl": "https://paypal.com.verify-account-security.com",
        }
    )

    assert official.features["IsKnownOfficialDomain"] == 1.0
    assert official.features["IsKnownOfficialSubdomain"] == 1.0
    assert official.features["BrandInDeceptivePosition"] == 0.0
    assert deceptive.features["BrandInDeceptivePosition"] == 1.0
    assert deceptive.evidence["domainIdentity"]["impersonatedBrand"] == "PayPal"
    assert deceptive.evidence["domainIdentity"]["effectiveRegistrableDomain"] == "verify-account-security.com"


def test_feature_extraction_identifies_at_symbol_and_shortener() -> None:
    obfuscated = extract_features(
        {
            "requestId": "scan-at-symbol",
            "normalizedUrl": "https://google.com@evil-login.com",
        }
    )
    shortened = extract_features(
        {
            "requestId": "scan-shortener",
            "normalizedUrl": "https://bit.ly/example",
        }
    )

    assert obfuscated.features["HasAtSymbol"] == 1.0
    assert obfuscated.evidence["domainIdentity"]["effectiveRegistrableDomain"] == "evil-login.com"
    assert shortened.features["IsShorteningService"] == 1.0


def test_feature_extraction_recognises_common_domestic_official_domains() -> None:
    domestic_urls = (
        "https://www.jd.com/",
        "https://weibo.com/",
        "https://www.zhihu.com/",
        "https://www.gov.cn/",
        "https://www.huawei.com/",
        "https://www.mi.com/",
        "https://www.sina.com.cn/",
    )
    for index, url in enumerate(domestic_urls):
        result = extract_features(
            {
                "requestId": f"scan-domestic-{index}",
                "normalizedUrl": url,
            }
        )
        assert result.features["IsKnownOfficialDomain"] == 1.0
        assert result.evidence["domainIdentity"]["isKnownOfficialDomain"] is True


def test_feature_extraction_recognises_monash_official_domain_and_subdomain() -> None:
    official = extract_features(
        {
            "requestId": "scan-monash-official",
            "normalizedUrl": "https://www.monash.edu/",
        }
    )
    service = extract_features(
        {
            "requestId": "scan-monash-service",
            "normalizedUrl": "https://learning.monash.edu/",
        }
    )
    gitlab = extract_features(
        {
            "requestId": "scan-monash-gitlab",
            "normalizedUrl": "https://git.infotech.monash.edu/",
        }
    )

    assert official.features["IsKnownOfficialDomain"] == 1.0
    assert official.evidence["domainIdentity"]["registrableDomain"] == "monash.edu"
    assert service.features["IsKnownOfficialSubdomain"] == 1.0
    assert gitlab.features["IsKnownOfficialSubdomain"] == 1.0


def test_feature_extraction_recognises_google_drive_and_gitlab_official_services() -> None:
    google_drive = extract_features(
        {
            "requestId": "scan-google-drive",
            "normalizedUrl": "https://drive.google.com/",
        }
    )
    gitlab = extract_features(
        {
            "requestId": "scan-gitlab",
            "normalizedUrl": "https://gitlab.com/",
        }
    )

    assert google_drive.features["IsKnownOfficialDomain"] == 1.0
    assert google_drive.features["IsKnownOfficialSubdomain"] == 1.0
    assert gitlab.features["IsKnownOfficialDomain"] == 1.0


def test_brand_identity_evidence_records_digit_substitution_details() -> None:
    result = extract_features(
        {
            "requestId": "scan-brand-substitution",
            "normalizedUrl": "https://g00gle.com/",
        }
    )
    identity = result.evidence["domainIdentity"]

    assert identity["hasDigitLetterSubstitution"] is True
    assert identity["digitLetterSubstitutions"] == [
        {"position": 1, "observed": "0", "expected": "o"},
        {"position": 2, "observed": "0", "expected": "o"},
    ]
    assert "digit_letter_substitution" in identity["impersonationTechniques"]


def test_pipeline_returns_frontend_fields_when_model_exists() -> None:
    artifact = PROJECT_ROOT / "artifacts" / "phishing_detection_model.joblib"
    if not artifact.exists():
        return
    result = analyze_submission(
        {
            "requestId": f"scan-test-{uuid4().hex}",
            "url": "https://portal.example.com/login",
            "html": "<html><head><title>Portal Login</title></head><body><form><input type='password'></form></body></html>",
        }
    )
    assert result["frontend"]["riskCategory"] in {"Safe", "Suspicious", "High Risk"}
    assert 0 <= result["frontend"]["riskScore"] <= 100
    assert result["frontend"]["verification"]["code"]
    assert result["frontend"]["verification"]["label"]
    assert result["frontend"]["verification"]["detail"]


def test_enrich_submission_with_web_content_applies_fetch_result(monkeypatch) -> None:
    html = """
    <html>
      <head><title>Trello Board</title></head>
      <body>
        <a href="https://trello.com/home">Home</a>
        <script src="/app.js"></script>
      </body>
    </html>
    """.strip()

    def fake_fetch(url: str, *, timeout_seconds: float = 8.0, max_bytes: int = 1_500_000) -> WebFetchResult:
        assert url == "https://trello.com/b/Upebaw8l/fit5238group15"
        return WebFetchResult(
            html=html,
            final_url="https://trello.com/b/Upebaw8l/fit5238group15",
            redirect_chain=["https://trello.com/login", "https://trello.com/b/Upebaw8l/fit5238group15"],
            warnings=[],
            fetch_status="success",
        )

    monkeypatch.setattr("app.services.web_fetch.fetch_web_content", fake_fetch)
    submission = PreprocessedSubmission(
        request_id="scan-test-fetch",
        raw_url="https://trello.com/b/Upebaw8l/fit5238group15",
        normalized_url="https://trello.com/b/Upebaw8l/fit5238group15",
        domain="trello.com",
        scheme="https",
    )

    enriched = enrich_submission_with_web_content(submission)
    extracted = extract_features(enriched.to_feature_input())

    assert enriched.final_url == "https://trello.com/b/Upebaw8l/fit5238group15"
    assert enriched.redirect_chain
    assert enriched.fetch_status == "success"
    assert extracted.features["HTMLAvailable"] == 1.0
    assert extracted.features["HasTitle"] == 1.0


def test_pipeline_marks_unable_to_verify_without_forcing_high_risk(monkeypatch) -> None:
    def fake_fetch(url: str, *, timeout_seconds: float = 8.0, max_bytes: int = 1_500_000) -> WebFetchResult:
        return WebFetchResult(
            html=None,
            final_url=None,
            redirect_chain=[],
            warnings=["Automatic webpage fetch failed before HTML could be collected."],
            fetch_status="network_error",
        )

    monkeypatch.setattr("app.services.web_fetch.fetch_web_content", fake_fetch)
    result = analyze_submission(
        {
            "requestId": f"scan-unable-{uuid4().hex}",
            "url": "https://abcdef123456789.com",
        }
    )
    assert result["frontend"]["verification"]["code"] == "UNABLE_TO_VERIFY"
    assert result["frontend"]["riskCategory"] == "Suspicious"


def test_pipeline_keeps_known_monash_learning_service_safe_when_web_fetch_fails(monkeypatch) -> None:
    def fake_fetch(url: str, *, timeout_seconds: float = 8.0, max_bytes: int = 1_500_000) -> WebFetchResult:
        assert url == "https://learning.monash.edu/my/"
        return WebFetchResult(
            html=None,
            final_url=None,
            redirect_chain=[],
            warnings=["Automatic webpage fetch failed before HTML could be collected."],
            fetch_status="network_error",
        )

    monkeypatch.setattr("app.services.web_fetch.fetch_web_content", fake_fetch)
    result = analyze_submission(
        {
            "requestId": f"scan-monash-learning-{uuid4().hex}",
            "url": "https://learning.monash.edu/my/",
        }
    )

    assert result["featureExtraction"]["features"]["IsKnownOfficialSubdomain"] == 1.0
    assert result["frontend"]["verification"]["code"] == "OFFICIAL_DOMAIN_ONLY"
    assert result["frontend"]["riskCategory"] == "Safe"
    assert result["frontend"]["safetyScore"] >= 65


def test_pipeline_keeps_known_monash_login_page_safe_when_webpage_is_verified(monkeypatch) -> None:
    html = """
    <html>
      <head><title>Monash University Sign In</title></head>
      <body>
        <form action="/login">
          <input type="text" name="username">
          <input type="password" name="password">
        </form>
      </body>
    </html>
    """

    def fake_fetch(url: str, *, timeout_seconds: float = 8.0, max_bytes: int = 1_500_000) -> WebFetchResult:
        assert url == "https://learning.monash.edu/my/"
        return WebFetchResult(
            html=html,
            final_url="https://monashuni.okta.com/app/learning",
            redirect_chain=["https://monashuni.okta.com/app/learning"],
            warnings=[],
            fetch_status="success",
        )

    monkeypatch.setattr("app.services.web_fetch.fetch_web_content", fake_fetch)
    result = analyze_submission(
        {
            "requestId": f"scan-monash-login-{uuid4().hex}",
            "url": "https://learning.monash.edu/my/",
        }
    )

    assert result["featureExtraction"]["features"]["HasLoginForm"] == 1.0
    assert result["frontend"]["verification"]["code"] == "WEBPAGE_VERIFIED"
    assert result["frontend"]["riskCategory"] == "Safe"
    assert result["frontend"]["safetyScore"] >= 65


def test_pipeline_uses_allowlist_override_before_model_analysis() -> None:
    request_id = f"scan-allowlist-{uuid4().hex}"
    url = "https://trusted-admin-review.example.com/login"
    initial = analyze_submission({"requestId": request_id, "url": url})
    report_response = m5_service.report_website(
        {
            "requestId": request_id,
            "url": initial["preprocessing"]["normalizedUrl"],
            "reviewType": "request_recheck",
            "employeeAssessment": "Safe",
            "reasonCode": "official_service",
            "comment": "Known official portal",
        }
    )
    feedback_repository.resolve_case(
        case_id=report_response.body["caseId"],
        decision="allowlist",
        reason="Validated by admin as a trusted internal portal.",
        decided_by_email="admin@clearurl.local",
        decided_by_name="ClearURL Administrator",
    )

    result = analyze_submission({"requestId": f"scan-allowlist-hit-{uuid4().hex}", "url": url})
    assert result["frontend"]["riskCategory"] == "Safe"
    assert result["frontend"]["verification"]["code"] == "ADMIN_ALLOWLIST_MATCH"
    assert result["prediction"]["model_name"] == "policy-allowlist"


def test_pipeline_uses_active_temporary_allowlist_override_before_model_analysis() -> None:
    request_id = f"scan-temporary-allowlist-{uuid4().hex}"
    url = "https://temporary-admin-review.example.com/login"
    initial = analyze_submission({"requestId": request_id, "url": url})
    report_response = m5_service.report_website(
        {
            "requestId": request_id,
            "url": initial["preprocessing"]["normalizedUrl"],
            "reviewType": "request_recheck",
            "employeeAssessment": "Safe",
            "reasonCode": "official_service",
            "comment": "Trusted temporary supplier portal",
        }
    )
    feedback_repository.resolve_case(
        case_id=report_response.body["caseId"],
        decision="allowlist",
        reason="Temporary approval for a verified supplier portal.",
        decided_by_email="admin@clearurl.local",
        decided_by_name="ClearURL Administrator",
        allowlist_expiry_days=7,
    )

    policy_entry = feedback_repository.lookup_policy(initial["preprocessing"]["normalizedUrl"])
    result = analyze_submission({"requestId": f"scan-temporary-hit-{uuid4().hex}", "url": url})

    assert policy_entry is not None
    assert policy_entry["expires_at"] is not None
    assert result["frontend"]["verification"]["code"] == "ADMIN_ALLOWLIST_MATCH"


def test_expired_allowlist_entry_no_longer_overrides_model_analysis() -> None:
    request_id = f"scan-expired-allowlist-{uuid4().hex}"
    url = "https://expired-admin-review.example.com/"
    initial = analyze_submission({"requestId": request_id, "url": url})
    report_response = m5_service.report_website(
        {
            "requestId": request_id,
            "url": initial["preprocessing"]["normalizedUrl"],
            "reviewType": "request_recheck",
            "employeeAssessment": "Safe",
            "reasonCode": "official_service",
            "comment": "This portal was only temporarily approved.",
        }
    )
    feedback_repository.resolve_case(
        case_id=report_response.body["caseId"],
        decision="allowlist",
        reason="Temporary approval that has now expired.",
        decided_by_email="admin@clearurl.local",
        decided_by_name="ClearURL Administrator",
        allowlist_expiry_days=1,
    )
    with feedback_repository._connect() as connection, connection:
        connection.execute(
            "UPDATE policy_entries SET expires_at = ? WHERE source_case_id = ?",
            ("2000-01-01T00:00:00Z", report_response.body["caseId"]),
        )

    entries = feedback_repository.list_policy_entries()
    entry = next(item for item in entries if item["source_case_id"] == report_response.body["caseId"])

    assert feedback_repository.lookup_policy(initial["preprocessing"]["normalizedUrl"]) is None
    assert entry["policy_status"] == "expired"


def test_pipeline_uses_blocklist_override_before_model_analysis() -> None:
    request_id = f"scan-blocklist-{uuid4().hex}"
    url = "https://confirmed-phishing-admin.example.com/login"
    initial = analyze_submission({"requestId": request_id, "url": url})
    report_response = m5_service.report_website(
        {
            "requestId": request_id,
            "url": initial["preprocessing"]["normalizedUrl"],
            "reviewType": "report_suspicious",
            "employeeAssessment": "High Risk",
            "reasonCode": "brand_impersonation",
            "comment": "Confirmed phishing attempt",
        }
    )
    feedback_repository.resolve_case(
        case_id=report_response.body["caseId"],
        decision="blocklist",
        reason="Confirmed phishing behaviour by admin review.",
        decided_by_email="admin@clearurl.local",
        decided_by_name="ClearURL Administrator",
    )

    result = analyze_submission({"requestId": f"scan-blocklist-hit-{uuid4().hex}", "url": url})
    assert result["frontend"]["riskCategory"] == "High Risk"
    assert result["frontend"]["verification"]["code"] == "ADMIN_BLOCKLIST_MATCH"
    assert result["prediction"]["model_name"] == "policy-blocklist"
