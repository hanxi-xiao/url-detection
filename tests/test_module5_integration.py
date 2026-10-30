from pathlib import Path
from uuid import uuid4

from app.config import DEFAULT_MODEL_ARTIFACT
from app.module5 import ExplanationService, PredictionContext
from app.services.pipeline import analyze_submission, m5_service


def test_analyze_includes_module5_fields_when_model_exists() -> None:
    if not DEFAULT_MODEL_ARTIFACT.exists():
        return
    result = analyze_submission(
        {
            "requestId": f"scan-m5-{uuid4().hex}",
            "url": "http://198.51.100.42/secure-login?verify=account",
            "html": "<html><head><title>Secure Account Login</title></head><body><form action='https://collector.example.net/submit'><input name='username'><input type='password'></form></body></html>",
        }
    )
    assert result["reasons"]
    assert result["recommendations"]
    assert result["frontend"]["reasons"]
    assert result["prediction"]["explanationMode"] in {
        "tree-shap-local-contributions",
        "feature-impact-proxy",
    }


def test_report_endpoint_logic_after_analysis() -> None:
    if not DEFAULT_MODEL_ARTIFACT.exists():
        return
    request_id = f"scan-m5-{uuid4().hex}"
    normalized_url = "https://portal.example.com/login"
    analyze_submission(
        {
            "requestId": request_id,
            "url": normalized_url,
            "html": "<html><head><title>Portal Login</title></head><body><form><input type='password'></form></body></html>",
        }
    )
    response = m5_service.report_website(
        {
            "requestId": request_id,
            "url": normalized_url,
            "reviewType": "report_suspicious",
            "employeeAssessment": "High Risk",
            "reasonCode": "credential_request",
            "comment": "Looks suspicious",
        }
    )
    assert response.status_code in {200, 201}


def test_brand_impersonation_reason_names_the_matched_domain() -> None:
    result = ExplanationService().explain(
        PredictionContext.from_mapping(
            {
                "requestId": "scan-brand-explanation",
                "normalizedUrl": "https://go0gle.com/",
                "modelVersion": "test-model",
                "featureSchemaVersion": "clearurl-m3-v2",
                "features": {
                    "BrandSimilarityScore": 1.0,
                    "HasBrandImpersonation": 1.0,
                    "HTMLAvailable": 0.0,
                },
                "evidence": {
                    "domainIdentity": {
                        "impersonatedBrand": "Google",
                        "impersonatedDomain": "google.com",
                    },
                    "webEvidence": {"available": False},
                },
                "phishingProbability": 0.95,
                "riskScore": 95.0,
                "riskCategory": "High Risk",
            }
        ),
        [],
    )
    assert result.reasons[0].title == "Possible brand impersonation"
    assert "google.com" in result.reasons[0].detail
    assert "does not by itself prove" in result.reasons[1].detail


def test_report_endpoint_rejects_conflicting_review_assessment() -> None:
    response = m5_service.report_website(
        {
            "requestId": "scan-invalid-review",
            "url": "https://portal.example.com/login",
            "reviewType": "report_suspicious",
            "employeeAssessment": "Safe",
            "reasonCode": "official_service",
            "comment": "Conflicting feedback",
        }
    )
    assert response.status_code == 400
    assert response.body["error"]["code"] == "INVALID_REPORT_REQUEST"


def test_result_review_allows_employee_to_escalate_a_safe_result() -> None:
    request_id = f"scan-review-escalation-{uuid4().hex}"
    normalized_url = "https://safe-result-review.example.com/"
    analyze_submission(
        {
            "requestId": request_id,
            "url": normalized_url,
            "html": "<html><head><title>Example</title></head><body></body></html>",
        }
    )
    response = m5_service.report_website(
        {
            "requestId": request_id,
            "url": normalized_url,
            "reviewType": "request_recheck",
            "employeeAssessment": "High Risk",
            "reasonCode": "risk_underestimated",
            "comment": "The link was received in an unexpected message.",
        }
    )
    assert response.status_code in {200, 201}
