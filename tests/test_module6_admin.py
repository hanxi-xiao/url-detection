from uuid import uuid4

from app.module6.admin_data import (
    build_brand_impersonation_visuals,
    build_cases,
    build_model_metrics,
    build_overview,
    build_review_insights,
)
from app.services.pipeline import analyze_submission, m5_service
from app.services.state import feedback_repository


def test_admin_overview_and_metrics_have_data() -> None:
    analyze_submission(
        {
            "requestId": f"scan-m6-{uuid4().hex}",
            "url": "https://portal.example.com/login",
            "html": "<html><head><title>Portal Login</title></head><body><form><input type='password'></form></body></html>",
        }
    )
    overview = build_overview()
    metrics = build_model_metrics()
    assert overview["summary"]["totalScans"] >= 1
    assert metrics is not None
    assert metrics["metrics"]["f1Score"] > 0


def test_admin_review_queue_preserves_employee_feedback_metadata() -> None:
    request_id = f"scan-m6-review-{uuid4().hex}"
    normalized_url = "https://trusted.example.com/login"
    analyze_submission(
        {
            "requestId": request_id,
            "url": normalized_url,
            "html": "<html><head><title>Trusted Login</title></head><body><form><input type='password'></form></body></html>",
        }
    )
    m5_service.report_website(
        {
            "requestId": request_id,
            "url": normalized_url,
            "reviewType": "request_recheck",
            "employeeAssessment": "Safe",
            "reasonCode": "official_service",
            "comment": "Known service used by the team.",
        }
    )

    rows = feedback_repository.list_feedback_for_review()
    row = next(item for item in rows if item["request_id"] == request_id)
    assert row["review_type"] == "request_recheck"
    assert row["employee_assessment"] == "Safe"
    assert row["reason_code"] == "official_service"
    assert row["comment"] == "Known service used by the team."


def test_admin_case_resolution_updates_status_and_policy_metadata() -> None:
    request_id = f"scan-m6-policy-{uuid4().hex}"
    normalized_url = "https://allowlisted-case.example.com/"
    analyze_submission(
        {
            "requestId": request_id,
            "url": normalized_url,
            "html": "<html><head><title>Trusted Site</title></head><body></body></html>",
        }
    )
    response = m5_service.report_website(
        {
            "requestId": request_id,
            "url": normalized_url,
            "reviewType": "request_recheck",
            "employeeAssessment": "Safe",
            "reasonCode": "official_service",
            "comment": "Known trusted service.",
        }
    )
    resolved = feedback_repository.resolve_case(
        case_id=response.body["caseId"],
        decision="allowlist",
        reason="Admin validated this URL as safe.",
        decided_by_email="admin@clearurl.local",
        decided_by_name="ClearURL Administrator",
        screenshot_name="portal.png",
        screenshot_data_url="data:image/png;base64,aGVsbG8=",
    )
    case = next(item for item in build_cases() if item["caseId"] == resolved["case_id"])
    assert case["status"] == "ALLOWLISTED"
    assert case["adminDecision"] == "allowlist"
    assert case["adminReason"] == "Admin validated this URL as safe."
    assert case["adminScreenshotName"] == "portal.png"


def test_policy_entry_removal_reopens_the_source_case_and_updates_insights() -> None:
    request_id = f"scan-m6-policy-removal-{uuid4().hex}"
    normalized_url = "https://removable-policy-entry.example.com/"
    analyze_submission(
        {
            "requestId": request_id,
            "url": normalized_url,
            "html": "<html><head><title>Review Needed</title></head><body></body></html>",
        }
    )
    response = m5_service.report_website(
        {
            "requestId": request_id,
            "url": normalized_url,
            "reviewType": "report_suspicious",
            "employeeAssessment": "High Risk",
            "reasonCode": "brand_impersonation",
            "comment": "The domain appears to imitate a known brand.",
        }
    )
    feedback_repository.resolve_case(
        case_id=response.body["caseId"],
        decision="blocklist",
        reason="Confirmed for temporary blocklist coverage.",
        decided_by_email="admin@clearurl.local",
        decided_by_name="ClearURL Administrator",
    )

    entry = next(
        item
        for item in feedback_repository.list_policy_entries()
        if item["source_case_id"] == response.body["caseId"]
    )
    removed = feedback_repository.remove_policy_entry(entry["entry_id"])
    reopened_case = feedback_repository.get_case(response.body["caseId"])
    insights = build_review_insights()

    assert removed is not None
    assert feedback_repository.lookup_policy(normalized_url) is None
    assert reopened_case is not None
    assert reopened_case["status"] == "REOPENED"
    assert any(item["reasonCode"] == "brand_impersonation" for item in insights["topReasons"])


def test_brand_impersonation_visualiser_returns_character_substitution_evidence() -> None:
    analyze_submission(
        {
            "requestId": f"scan-m6-brand-{uuid4().hex}",
            "url": "https://go0gle.com/",
        }
    )

    visualiser = build_brand_impersonation_visuals()
    item = next(row for row in visualiser["items"] if row["observedDomain"] == "go0gle.com")

    assert item["targetDomain"] == "google.com"
    assert item["targetBrand"] == "Google"
    assert "digit_letter_substitution" in item["techniques"]
    assert item["digitSubstitutions"][0]["observed"] == "0"
