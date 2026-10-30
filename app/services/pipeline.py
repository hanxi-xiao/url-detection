from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Any, Mapping

from app.config import DEFAULT_MODEL_ARTIFACT
from app.module2 import preprocess_submission
from app.module3 import extract_features
from app.module4 import DetectionModelService
from app.module4.service import has_strong_phishing_evidence
from app.module5 import build_feature_impacts
from app.module6.log_manager import save_prediction_log
from app.services.state import feedback_repository, m5_service
from app.services.web_fetch import enrich_submission_with_web_content


@dataclass(slots=True)
class PipelineError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return self.message


def build_verification_status(
    preprocessed,
    extraction,
) -> dict[str, str]:
    features = extraction.features
    warnings = list(preprocessed.warnings)
    html_available = features.get("HTMLAvailable", 0.0) >= 1.0
    official_identity = any(
        (
            features.get("IsKnownOfficialDomain", 0.0) >= 1.0,
            features.get("IsKnownOfficialSubdomain", 0.0) >= 1.0,
        )
    )
    is_shortener = features.get("IsShorteningService", 0.0) >= 1.0
    has_redirects = bool(preprocessed.redirect_chain)
    has_fetch_warning = bool(warnings)
    fetch_status = getattr(preprocessed, "fetch_status", "not_attempted")

    if html_available:
        return {
            "code": "WEBPAGE_VERIFIED",
            "label": "Webpage content verified",
            "detail": "The analysis included retrieved webpage content in addition to URL structure.",
        }
    if is_shortener and not has_redirects:
        return {
            "code": "SHORT_LINK_UNRESOLVED",
            "label": "Short-link destination not verified",
            "detail": "The URL belongs to a shortening service, but the final destination could not be confirmed from redirects or webpage content.",
        }
    if official_identity:
        return {
            "code": "OFFICIAL_DOMAIN_ONLY",
            "label": "Official domain recognised",
            "detail": "The domain matches a configured official service, but full webpage content was not available during analysis.",
        }
    if fetch_status == "network_error":
        return {
            "code": "UNABLE_TO_VERIFY",
            "label": "Destination could not be verified",
            "detail": "The system could not reach the website to confirm live webpage content or network availability.",
        }
    if fetch_status == "http_error":
        return {
            "code": "HTTP_ACCESS_FAILED",
            "label": "Webpage access failed",
            "detail": "The website returned an HTTP error before webpage content could be analysed.",
        }
    if has_fetch_warning:
        return {
            "code": "LIMITED_WEB_VERIFICATION",
            "label": "Webpage verification limited",
            "detail": "The URL structure was analysed, but webpage retrieval or validation could not be completed.",
        }
    return {
        "code": "URL_ONLY_ANALYSIS",
        "label": "URL-only analysis",
        "detail": "The result is based on URL structure and identity signals without confirmed webpage content.",
    }


def apply_verification_status_guardrail(
    risk_score_percent: float,
    risk_category: str,
    extraction,
    verification_status: Mapping[str, str],
) -> tuple[float, str]:
    code = verification_status.get("code", "")
    official_identity = any(
        (
            extraction.features.get("IsKnownOfficialDomain", 0.0) >= 1.0,
            extraction.features.get("IsKnownOfficialSubdomain", 0.0) >= 1.0,
        )
    )
    if official_identity and not has_strong_phishing_evidence(extraction.features):
        # Keep the final category stable for configured official services when
        # live HTML cannot be retrieved and no independent phishing signal exists.
        return min(risk_score_percent, 35.0), "Safe"
    if code != "UNABLE_TO_VERIFY":
        return risk_score_percent, risk_category
    if has_strong_phishing_evidence(extraction.features):
        return risk_score_percent, risk_category
    return 89.0, "Suspicious"


def analyze_submission(payload: Mapping[str, Any]) -> dict[str, Any]:
    started_at = perf_counter()
    preprocessed = preprocess_submission(dict(payload))
    policy_entry = feedback_repository.lookup_policy(preprocessed.normalized_url)
    if policy_entry is not None:
        return build_policy_override_response(preprocessed, policy_entry, started_at)
    preprocessed = enrich_submission_with_web_content(preprocessed)
    extraction = extract_features(preprocessed.to_feature_input())
    if not extraction.quality.is_valid:
        raise PipelineError("FEATURE_EXTRACTION_FAILED", "Feature extraction did not produce a valid vector.")

    service = DetectionModelService.load(DEFAULT_MODEL_ARTIFACT)
    prediction = service.predict_one(extraction.features)
    prediction_dict = prediction.to_dict()
    verification_status = build_verification_status(preprocessed, extraction)
    risk_score_percent, risk_category = apply_verification_status_guardrail(
        round(prediction.risk_score * 100, 2),
        prediction.risk_classification,
        extraction,
        verification_status,
    )
    safety_score_percent = round(100.0 - risk_score_percent, 2)
    prediction_dict["risk_score"] = round(risk_score_percent / 100.0, 4)
    prediction_dict["risk_score_percent"] = risk_score_percent
    prediction_dict["risk_classification"] = risk_category
    context = {
        "requestId": preprocessed.request_id,
        "normalizedUrl": preprocessed.normalized_url,
        "modelVersion": prediction.model_version,
        "featureSchemaVersion": extraction.feature_schema_version,
        "features": extraction.features,
        "evidence": {
            **extraction.evidence,
            "webEvidence": {
                "available": extraction.features.get("HTMLAvailable", 0.0) >= 1.0,
                "finalUrl": preprocessed.final_url,
                "warnings": list(preprocessed.warnings),
            },
        },
        "phishingProbability": prediction.phishing_probability,
        "riskScore": risk_score_percent,
        "riskCategory": risk_category,
    }
    explanation = m5_service.process_prediction(
        context,
        build_feature_impacts(
            extraction.features,
            extraction.normalized_features,
            service.feature_importances(),
            local_contributions=prediction.feature_contributions,
        ),
    )
    employee_fields = explanation.to_employee_fields()
    response_ms = (perf_counter() - started_at) * 1000.0
    explanation_mode = (
        "tree-shap-local-contributions"
        if prediction.feature_contributions
        else "feature-impact-proxy"
    )
    save_prediction_log(
        request_id=preprocessed.request_id,
        normalized_url=preprocessed.normalized_url,
        risk_score=risk_score_percent,
        risk_label=risk_category,
        phishing_probability=prediction.phishing_probability,
        model_name=prediction.model_name,
        model_version=prediction.model_version,
        response_ms=response_ms,
    )

    return {
        "requestId": preprocessed.request_id,
        "preprocessing": preprocessed.to_api_dict(),
        "featureExtraction": extraction.to_api_dict(),
        "prediction": {
            **prediction_dict,
            "explanationMode": explanation_mode,
            "responseMs": round(response_ms, 3),
        },
        "verification": verification_status,
        "explainability": explanation.to_internal_dict(),
        "frontend": {
            "requestId": preprocessed.request_id,
            "normalizedUrl": preprocessed.normalized_url,
            "riskScore": round(risk_score_percent),
            "safetyScore": round(safety_score_percent),
            "riskCategory": risk_category,
            "verification": verification_status,
            "reasons": employee_fields["reasons"],
            "recommendations": employee_fields["recommendations"],
        },
        "reasons": employee_fields["reasons"],
        "recommendations": employee_fields["recommendations"],
    }


def build_policy_override_response(preprocessed, policy_entry: Mapping[str, Any], started_at: float) -> dict[str, Any]:
    list_type = str(policy_entry["list_type"])
    is_allowlist = list_type == "allowlist"
    risk_category = "Safe" if is_allowlist else "High Risk"
    risk_score_percent = 0.0 if is_allowlist else 100.0
    safety_score_percent = 100.0 - risk_score_percent
    verification_status = {
        "code": "ADMIN_ALLOWLIST_MATCH" if is_allowlist else "ADMIN_BLOCKLIST_MATCH",
        "label": "Admin allowlist match" if is_allowlist else "Admin blocklist match",
        "detail": (
            "This URL matched a reviewed admin allowlist entry and the stored decision overrides model inference."
            if is_allowlist
            else "This URL matched a reviewed admin blocklist entry and the stored decision overrides model inference."
        ),
    }
    context = {
        "requestId": preprocessed.request_id,
        "normalizedUrl": preprocessed.normalized_url,
        "modelVersion": f"policy-{list_type}-override-v1",
        "featureSchemaVersion": "policy-override-v1",
        "features": {
            "PolicyOverrideMatched": 1.0,
        },
        "evidence": {
            "policyOverride": {
                "listType": list_type,
                "reason": policy_entry.get("decision_reason"),
                "decidedBy": policy_entry.get("decided_by_name"),
                "expiresAt": policy_entry.get("expires_at"),
            },
            "webEvidence": {
                "available": False,
                "finalUrl": preprocessed.normalized_url,
                "warnings": ["Result overridden by reviewed admin decision."],
            },
        },
        "phishingProbability": 0.0 if is_allowlist else 1.0,
        "riskScore": risk_score_percent,
        "riskCategory": risk_category,
    }
    explanation = m5_service.process_prediction(context, [])
    employee_fields = explanation.to_employee_fields()
    response_ms = (perf_counter() - started_at) * 1000.0
    save_prediction_log(
        request_id=preprocessed.request_id,
        normalized_url=preprocessed.normalized_url,
        risk_score=risk_score_percent,
        risk_label=risk_category,
        phishing_probability=0.0 if is_allowlist else 1.0,
        model_name=f"policy-{list_type}",
        model_version=f"policy-{list_type}-override-v1",
        response_ms=response_ms,
    )
    return {
        "requestId": preprocessed.request_id,
        "preprocessing": preprocessed.to_api_dict(),
        "featureExtraction": {
            "requestId": preprocessed.request_id,
            "normalizedUrl": preprocessed.normalized_url,
            "featureSchemaVersion": "policy-override-v1",
            "features": {"PolicyOverrideMatched": 1.0},
            "normalizedFeatures": {"PolicyOverrideMatched": 1.0},
            "featureOrder": ["PolicyOverrideMatched"],
            "featureVector": [1.0],
            "quality": {
                "isValid": True,
                "missingFeatures": [],
                "imputedFeatures": [],
                "outOfRangeFeatures": [],
                "warnings": ["Prediction overridden by reviewed admin decision."],
            },
        },
        "prediction": {
            "prediction": "legitimate" if is_allowlist else "phishing",
            "predicted_class": 0 if is_allowlist else 1,
            "phishing_probability": 0.0 if is_allowlist else 1.0,
            "risk_score": round(risk_score_percent / 100.0, 4),
            "risk_score_percent": risk_score_percent,
            "risk_classification": risk_category,
            "model_name": f"policy-{list_type}",
            "model_version": f"policy-{list_type}-override-v1",
            "explanationMode": "policy-override",
            "responseMs": round(response_ms, 3),
        },
        "verification": verification_status,
        "explainability": explanation.to_internal_dict(),
        "frontend": {
            "requestId": preprocessed.request_id,
            "normalizedUrl": preprocessed.normalized_url,
            "riskScore": round(risk_score_percent),
            "safetyScore": round(safety_score_percent),
            "riskCategory": risk_category,
            "verification": verification_status,
            "reasons": employee_fields["reasons"],
            "recommendations": employee_fields["recommendations"],
        },
        "reasons": employee_fields["reasons"],
        "recommendations": employee_fields["recommendations"],
    }
