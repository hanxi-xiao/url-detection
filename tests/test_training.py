from pathlib import Path

import pandas as pd

from app.module4.data import prepare_dataset
from app.module4.modeling import save_model_bundle, train_and_compare
from app.module4.risk import RiskThresholds
from app.module4.service import (
    DetectionModelService,
    apply_benign_evidence_guardrail,
    apply_high_risk_guardrail,
    apply_missing_web_evidence_guardrail,
    has_strong_benign_evidence,
    has_strong_phishing_evidence,
)


def test_training_and_prediction_roundtrip(tmp_path: Path) -> None:
    rows = []
    for index in range(12):
        rows.append(
            {
                "URLLength": 20 + index,
                "DomainLength": 10 + (index % 4),
                "NoOfSpecialCharsInURL": 2 + (index % 3),
                "IsDomainIP": 0,
                "NoOfSubDomain": index % 2,
                "HasSuspiciousPattern": 0,
                "SuspiciousPatternCount": 0,
                "UsesHTTPS": 1,
                "NoOfPasswordFields": 0,
                "HasLoginForm": 0,
                "HasExternalFormSubmit": 0,
                "NoOfIFrames": 0,
                "label": 0,
            }
        )
    for index in range(12):
        rows.append(
            {
                "URLLength": 90 + index,
                "DomainLength": 28 + (index % 3),
                "NoOfSpecialCharsInURL": 12 + (index % 4),
                "IsDomainIP": 1,
                "NoOfSubDomain": 3,
                "HasSuspiciousPattern": 1,
                "SuspiciousPatternCount": 4 + (index % 3),
                "UsesHTTPS": 0,
                "NoOfPasswordFields": 1,
                "HasLoginForm": 1,
                "HasExternalFormSubmit": 1,
                "NoOfIFrames": 1,
                "label": 1,
            }
        )

    csv_path = tmp_path / "training.csv"
    pd.DataFrame(rows).to_csv(csv_path, index=False)
    dataset = prepare_dataset(csv_path, validation_size=0.25, test_size=0.25, random_state=7)
    outcome = train_and_compare(
        dataset.train_X,
        dataset.train_y,
        dataset.validation_X,
        dataset.validation_y,
        dataset.test_X,
        dataset.test_y,
        random_state=7,
    )
    artifact = save_model_bundle(
        tmp_path / "model.joblib",
        outcome=outcome,
        feature_names=dataset.feature_names,
        thresholds=RiskThresholds(),
        dataset_summary=dataset.summary(),
        selection_metric="f1",
        random_state=7,
        model_version="test-model-1",
        dataset_version="test-data-1",
    )
    service = DetectionModelService.load(artifact)
    result = service.predict_one(dataset.test_X.iloc[0].to_dict())
    assert result.risk_classification in {"Safe", "Suspicious", "High Risk"}
    assert 0.0 <= result.phishing_probability <= 1.0


def test_high_risk_guardrail_caps_weak_signals() -> None:
    thresholds = RiskThresholds(suspicious=0.45, high_risk=0.9)
    weak_record = {
        "URLLength": 24,
        "DomainLength": 15,
        "NoOfSpecialCharsInURL": 6,
        "IsDomainIP": 0,
        "NoOfSubDomain": 1,
        "HasSuspiciousPattern": 0,
        "SuspiciousPatternCount": 0,
        "UsesHTTPS": 1,
        "NoOfPasswordFields": 0,
        "HasLoginForm": 0,
        "HasExternalFormSubmit": 0,
        "NoOfIFrames": 0,
        "RedirectCount": 1,
    }
    assert not has_strong_phishing_evidence(weak_record)
    assert apply_high_risk_guardrail(0.98, weak_record, thresholds) == 0.89


def test_high_risk_guardrail_allows_strong_signals() -> None:
    thresholds = RiskThresholds(suspicious=0.45, high_risk=0.9)
    strong_record = {
        "URLLength": 108,
        "DomainLength": 27,
        "NoOfSpecialCharsInURL": 14,
        "IsDomainIP": 1,
        "NoOfSubDomain": 4,
        "HasSuspiciousPattern": 1,
        "SuspiciousPatternCount": 3,
        "UsesHTTPS": 0,
        "NoOfPasswordFields": 1,
        "HasLoginForm": 1,
        "HasExternalFormSubmit": 1,
        "NoOfIFrames": 1,
        "RedirectCount": 4,
    }
    assert has_strong_phishing_evidence(strong_record)
    assert apply_high_risk_guardrail(0.98, strong_record, thresholds) == 0.98


def test_known_official_login_form_is_not_a_standalone_phishing_signal() -> None:
    official_login_record = {
        "IsKnownOfficialDomain": 1,
        "IsKnownOfficialSubdomain": 1,
        "UsesHTTPS": 1,
        "HasLoginForm": 1,
        "NoOfPasswordFields": 1,
        "HasExternalFormSubmit": 0,
        "HasBrandImpersonation": 0,
        "BrandInDeceptivePosition": 0,
        "HasAtSymbol": 0,
        "IsDomainIP": 0,
    }

    assert not has_strong_phishing_evidence(official_login_record)


def test_missing_web_evidence_guardrail_downgrades_weak_signals() -> None:
    thresholds = RiskThresholds(suspicious=0.45, high_risk=0.9)
    weak_record = {
        "URLLength": 24,
        "DomainLength": 15,
        "NoOfSpecialCharsInURL": 6,
        "IsDomainIP": 0,
        "NoOfSubDomain": 1,
        "HasSuspiciousPattern": 0,
        "SuspiciousPatternCount": 0,
        "UsesHTTPS": 1,
        "NoOfPasswordFields": 0,
        "HasLoginForm": 0,
        "HasExternalFormSubmit": 0,
        "NoOfIFrames": 0,
        "HTMLAvailable": 0,
    }
    assert apply_missing_web_evidence_guardrail(0.89, weak_record, thresholds) == 0.89


def test_missing_web_evidence_guardrail_downgrades_known_official_domain() -> None:
    thresholds = RiskThresholds(suspicious=0.45, high_risk=0.9)
    official_record = {
        "URLLength": 27,
        "DomainLength": 19,
        "NoOfSpecialCharsInURL": 5,
        "IsDomainIP": 0,
        "NoOfSubDomain": 1,
        "HasSuspiciousPattern": 1,
        "SuspiciousPatternCount": 1,
        "HasSensitiveKeyword": 1,
        "SensitiveKeywordCount": 1,
        "HasLongSensitivePath": 0,
        "UsesHTTPS": 1,
        "NoOfPasswordFields": 0,
        "HasLoginForm": 0,
        "HasExternalFormSubmit": 0,
        "NoOfIFrames": 0,
        "HTMLAvailable": 0,
        "IsKnownOfficialDomain": 1,
        "IsKnownOfficialSubdomain": 1,
    }
    assert not has_strong_phishing_evidence(official_record)
    assert apply_missing_web_evidence_guardrail(0.92, official_record, thresholds) == 0.35


def test_missing_web_evidence_guardrail_keeps_strong_signals() -> None:
    thresholds = RiskThresholds(suspicious=0.45, high_risk=0.9)
    strong_record = {
        "URLLength": 108,
        "DomainLength": 27,
        "NoOfSpecialCharsInURL": 14,
        "IsDomainIP": 1,
        "NoOfSubDomain": 4,
        "HasSuspiciousPattern": 1,
        "SuspiciousPatternCount": 3,
        "UsesHTTPS": 0,
        "NoOfPasswordFields": 1,
        "HasLoginForm": 1,
        "HasExternalFormSubmit": 1,
        "NoOfIFrames": 1,
        "HTMLAvailable": 0,
    }
    assert apply_missing_web_evidence_guardrail(0.98, strong_record, thresholds) == 0.98


def test_benign_evidence_guardrail_downgrades_known_safe_pattern() -> None:
    thresholds = RiskThresholds(suspicious=0.45, high_risk=0.9)
    benign_record = {
        "HTMLAvailable": 1,
        "DomainTitleMatch": 1,
        "TitleDomainTokenOverlap": 1,
        "UsesHTTPS": 1,
        "IsDomainIP": 0,
        "HasSuspiciousPattern": 0,
        "SuspiciousPatternCount": 0,
        "NoOfPasswordFields": 0,
        "HasLoginForm": 0,
        "HasExternalFormSubmit": 0,
        "NoOfSubDomain": 1,
    }
    assert has_strong_benign_evidence(benign_record)
    assert apply_benign_evidence_guardrail(0.89, benign_record, thresholds) == 0.35
