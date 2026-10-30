# ClearURL Testing Record #6

## Document Information

- Project: `ClearURL`
- Repository: `url-detection-main`
- Document Type: `Testing Record`
- Purpose: Current-model regression and input-specific explainability verification
- Date: `2026-08-06`

## Version Under Test

- Model name: `xgboost`
- Model version: `xgboost-20260806T132636Z`
- Dataset version: `phiusiil-v7-contextual-explanations`
- Feature schema: `clearurl-m3-v2`
- Feature count: `16`
- Explanation mode: `tree-shap-local-contributions`

## Automated Verification

| Record ID | Area | Test Method | Expected Result | Actual Output | Status |
| --- | --- | --- | --- | --- | --- |
| AUTO-006-01 | Backend regression | `conda run --no-capture-output -n torch3.10 python -m pytest -q` | All backend and integration tests pass | `.................. [100%]`; `18 passed in 2.06s` | Pass |
| AUTO-006-02 | Frontend production build | `npm run build` | TypeScript compilation and Vite production build complete | `16 modules transformed`; generated `dist/index.html`, CSS, and JavaScript bundles; build completed in `276ms` | Pass |
| AUTO-006-03 | Model loading | Load `artifacts/phishing_detection_model.joblib` | Active model loads with the current schema | Model `xgboost-20260806T132636Z` loaded with `16` features and thresholds `0.45/0.90` | Pass |
| AUTO-006-04 | Local explanation | Inspect prediction response | Response identifies the active explanation mode and returns reasons | `explanationMode=tree-shap-local-contributions`; response includes `feature_contributions` for all 16 model features | Pass |

## Input-Specific Explainability Tests

| Record ID | Input | Expected Result | Actual Output | Status |
| --- | --- | --- | --- | --- |
| EXPL-006-01 | `https://go0gle.com/` | Detect a possible impersonation of Google and identify the target domain | Classification: `High Risk`; internal risk score: `99.87/100`; safety score: `0/100`; reason: `The domain closely resembles google.com (Google), which can indicate a typosquatting attempt.` | Pass |
| EXPL-006-02 | `https://baid0.com/` | Detect a possible impersonation of Baidu and identify the target domain | Classification: `High Risk`; internal risk score: `99.87/100`; safety score: `0/100`; reason: `The domain closely resembles baidu.com (Baidu), which can indicate a typosquatting attempt.` | Pass |
| EXPL-006-03 | `https://www.baidu.com/` | Do not report brand impersonation for the exact monitored domain | Classification: `Safe`; internal risk score: `44/100`; safety score: `56/100`; no brand-impersonation reason returned | Pass |
| EXPL-006-04 | `https://www.baidu.com/` with remote HTML unavailable | Explain the limitation without treating it as proof of phishing | Reason: `The server could not retrieve complete webpage content. This limits the analysis but does not by itself prove that the URL is phishing.` | Pass |

## Model Evaluation Record

| Metric | Result |
| --- | ---: |
| Accuracy | `0.9961810254` |
| Precision | `0.9952581665` |
| Recall | `0.9880999085` |
| F1-score | `0.9916661198` |
| ROC-AUC | `0.9992768061` |

The confusion matrix was `[[25572, 36], [91, 7556]]`, using the ordering
`[[safe predicted safe, safe predicted phishing], [phishing predicted safe, phishing predicted phishing]]`.

## Raw Output Samples

The following outputs were captured from direct calls to the local pipeline after
retraining. The internal risk score is used by the backend and the safety score is
the user-facing value returned to the frontend.

### Official Domain

Input:

```text
https://www.baidu.com/
```

Relevant output:

```text
modelVersion: xgboost-20260806T132636Z
prediction: phishing
phishingProbability: 0.995236337184906
riskScore: 44.0
riskClassification: Safe
safetyScore: 56
explanationMode: tree-shap-local-contributions
reasons:
  - Webpage evidence unavailable
  - URL length appears less suspicious
  - Encrypted connection available
```

The raw model probability remains high because the remote server did not provide
complete webpage evidence. The pipeline guardrail reduced the final risk score and
classified the result as `Safe`; the employee-facing interface uses the derived
safety score.

### Possible Google Typosquat

Input:

```text
https://go0gle.com/
```

Relevant output:

```text
modelVersion: xgboost-20260806T132636Z
prediction: phishing
phishingProbability: 0.9986925721168518
riskScore: 99.87
riskClassification: High Risk
safetyScore: 0
explanationMode: tree-shap-local-contributions
reasons:
  - Possible brand impersonation:
    The domain closely resembles google.com (Google), which can indicate a typosquatting attempt.
  - Webpage evidence unavailable:
    This limits the analysis but does not by itself prove that the URL is phishing.
```

### Possible Baidu Typosquat

Input:

```text
https://baid0.com/
```

Relevant output:

```text
modelVersion: xgboost-20260806T132636Z
prediction: phishing
phishingProbability: 0.9987221360206604
riskScore: 99.87
riskClassification: High Risk
safetyScore: 0
explanationMode: tree-shap-local-contributions
reasons:
  - Possible brand impersonation:
    The domain closely resembles baidu.com (Baidu), which can indicate a typosquatting attempt.
  - Webpage evidence unavailable:
    This limits the analysis but does not by itself prove that the URL is phishing.
```

## Evidence And Limitations

The brand-impersonation explanation is produced from the extracted domain identity
evidence and is specific to the submitted domain. The model also provides local
XGBoost tree contribution values for the current feature vector. The monitored brand
list is not a complete reputation database, so an unrecognised typo domain may require
additional training data or external reputation sources.

When the deployment environment cannot retrieve a remote webpage, the system records
that limitation and continues with URL-level evidence. A failed retrieval alone is not
treated as proof that the URL is phishing.

## Sign-Off

| Reviewer | Role | Decision | Date | Notes |
| --- | --- | --- | --- | --- |
| Pending | Pending | Pending | Pending | Awaiting team review |
