# ClearURL Model Test Results

## Document Information

- Project: `ClearURL`
- Repository: `url-detection-main`
- Document Type: `Model test results`
- Prepared For: `Model selection, retraining traceability, and project handover`
- Date Recorded: `2026-08-06`

## 1. Purpose

This document records the current model evaluation for ClearURL after adding brand-impersonation features and local explanation support.

## 2. Dataset and Features

- Dataset version: `phiusiil-v7-contextual-explanations`
- Cleaned rows: `166,270`
- Train rows: `116,388`
- Validation rows: `16,627`
- Test rows: `33,255`
- Feature count: `16`

### Training Sources

- `examples/phiusiil_model_features.csv`
- `examples/hard_negative_safe_samples.csv`
- `examples/official_safe_sites.csv`
- `examples/brand_impersonation_samples.csv`

The additional data includes safe examples for recognised public websites and phishing-labelled typo-squatting examples such as `go0gle.com` and `baid0.com`.

### Selected Feature Set

1. `URLLength`
2. `DomainLength`
3. `NoOfSpecialCharsInURL`
4. `IsDomainIP`
5. `NoOfSubDomain`
6. `HasSuspiciousPattern`
7. `SuspiciousPatternCount`
8. `BrandSimilarityScore`
9. `HasBrandImpersonation`
10. `UsesHTTPS`
11. `NoOfPasswordFields`
12. `HasLoginForm`
13. `HasExternalFormSubmit`
14. `NoOfIFrames`
15. `DomainTitleMatch`
16. `TitleDomainTokenOverlap`

## 3. Model Comparison

| Model | Validation Precision | Validation F1 | Test Precision | Test F1 | Test ROC-AUC |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic Regression | `0.9704356866` | `0.9744791667` | `0.9650475456` | `0.9734914771` | `0.9984058828` |
| Random Forest | `0.9881889764` | `0.9863767357` | `0.9893700787` | `0.9876203576` | `0.9988707100` |
| XGBoost | `0.9947201690` | `0.9900157646` | `0.9952581665` | `0.9916661198` | `0.9992768061` |

### Selected Model

- Model name: `xgboost`
- Model version: `xgboost-20260806T132636Z`
- Selection metric: `precision`
- Suspicious threshold: `0.45`
- High-risk threshold: `0.90`

## 4. Final Test-Set Results

| Metric | Value |
| --- | ---: |
| Accuracy | `0.9961810254097129` |
| Precision | `0.9952581664910432` |
| Recall | `0.9880999084608343` |
| F1-score | `0.9916661198241354` |
| ROC-AUC | `0.9992768060703534` |
| False Positive Rate | `0.0014058106841611997` |
| False Negative Rate | `0.011900091539165686` |
| Average Inference Time | `0.001112921605926495 ms` |

### Confusion Matrix

| Actual / Predicted | Safe | Phishing |
| --- | ---: | ---: |
| Safe | `25572` | `36` |
| Phishing | `91` | `7556` |

## 5. Explainability Update

The active XGBoost model now returns per-input tree contribution values through the XGBoost `pred_contribs` interface. ClearURL uses these local contributions to rank model evidence for each submitted URL. The API labels this mode as:

```text
tree-shap-local-contributions
```

The result also includes contextual evidence that is not treated as proof of phishing:

- a domain closely matching a monitored brand is shown as a possible typo-squatting signal;
- unavailable webpage content is shown as an evidence limitation, not as proof that the URL is malicious.

## 6. Post-Retraining Sanity Checks

| URL pattern | Classification | Safety score | Expected explanation evidence |
| --- | --- | ---: | --- |
| `https://www.baidu.com/` | Safe | `56` | Webpage evidence limitation when remote HTML is unavailable |
| `https://go0gle.com/` | High Risk | `0` | Similarity to `google.com` and unavailable webpage evidence |
| `https://baid0.com/` | High Risk | `0` | Similarity to `baidu.com` and unavailable webpage evidence |
| Synthetic suspicious login URL | High Risk | `0` | URL and connection-risk indicators |

These checks are model and pipeline sanity checks. The exact result for a live website may vary when webpage retrieval succeeds, fails, redirects, or is blocked by the target site.

## 7. Current Artifact and Limitations

- Model artifact: `artifacts/phishing_detection_model.joblib`
- Training report: `artifacts/training_report.json`

The brand list is a monitored set of common domains, not a complete internet reputation service. The absence of webpage content is handled as uncertainty, and should not be interpreted as evidence that a URL is phishing.
