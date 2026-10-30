# ClearURL Final System Test Record

## Document Information

- Project: `ClearURL: Explainable AI-Based Phishing URL Detection System`
- Repository: `url-detection-main`
- Record ID: `TEST_RECORD_10_FINAL`
- Record Type: Final integrated regression and build verification
- Test Date: `2026-08-20`
- Test Environment: macOS, Conda environment `torch3.10`, Node.js/Vite local build
- Overall Status: **Pass for automated regression and production build**

## Version Under Test

- Active model: `xgboost`
- Model version: `xgboost-20260806T143316Z`
- Dataset version: `phiusiil-v9-official-domain-guardrails`
- Feature schema: `clearurl-m3-v3`
- Policy override schema: `policy-override-v1`
- Model artifact: `artifacts/phishing_detection_model.joblib`

## Test Objective

This final record verifies that the current integrated codebase builds successfully
and that the automated regression suite passes across the main functional areas:

1. authentication, CAPTCHA, registration, recovery codes, password operations, and role checks;
2. URL validation, normalisation, webpage retrieval handling, and feature extraction;
3. XGBoost model loading, prediction, risk guardrails, and held-out evaluation records;
4. URL-specific explanations, verification status, and employee feedback;
5. administrator review cases, allowlist/blocklist decisions, policy expiry, and policy removal;
6. administration monitoring, brand-impersonation visualisation, account management, and documentation availability;
7. frontend TypeScript validation and production bundling.

## Executed Commands

```bash
conda activate torch3.10
pytest -q
npm run build
```

## Automated Execution Results

| Record ID | Test Area | Command | Expected Result | Actual Result | Status |
| --- | --- | --- | --- | --- | --- |
| AUTO-010-01 | Backend regression suite | `pytest -q` | All automated regression tests pass. | `48 passed in 4.43s` | Pass |
| AUTO-010-02 | Frontend production build | `npm run build` | TypeScript compilation and Vite production build complete. | `16 modules transformed`; build completed in `138ms`. | Pass |
| AUTO-010-03 | Production output | `npm run build` | Production assets are generated without build errors. | `dist/index.html`, CSS bundle, and JavaScript bundle generated successfully. | Pass |

## Functional Coverage Results

| Record ID | Functional Area | Automated Coverage and Expected Behaviour | Recorded Result | Status |
| --- | --- | --- | --- | --- |
| AUTH-010-01 | Default authentication | Seeded Employee and Admin credentials authenticate and receive the correct role. | Verified by `test_default_accounts_can_authenticate`. | Pass |
| AUTH-010-02 | CAPTCHA protection | Login without CAPTCHA is rejected; a valid server-side challenge allows login. | Verified by `test_login_requires_human_confirmation`. | Pass |
| AUTH-010-03 | Sessions and roles | Valid Admin session passes role checks; deleted or invalid sessions are rejected. | Verified by `test_session_roundtrip_and_role_check`. | Pass |
| AUTH-010-04 | Account registration | Employee and Admin account registration creates active accounts with the requested supported role. | Verified by `test_employee_registration_creates_an_active_employee_account` and `test_admin_registration_creates_an_active_admin_account`. | Pass |
| AUTH-010-05 | Password security | Change-password validates current password, recovery code, CAPTCHA, password strength, and invalidates existing sessions after success. | Verified by three password-change tests. | Pass |
| AUTH-010-06 | Password recovery and suspension | Recovery-code reset accepts a valid saved code; suspended employees cannot authenticate. | Verified by reset-password and account-status tests. | Pass |
| URL-010-01 | URL preprocessing | A domain without a scheme receives `https://`; unsupported schemes are rejected. | Verified by `tests/test_module2.py`. | Pass |
| URL-010-02 | Webpage and redirect handling | Retrieved HTML, final URL, redirect chain, and retrieval state are incorporated before extraction. | Verified by `test_enrich_submission_with_web_content_applies_fetch_result`. | Pass |
| URL-010-03 | Unreachable destinations | Failed webpage retrieval returns an inability-to-verify status and does not automatically force High Risk. | Verified by `test_pipeline_marks_unable_to_verify_without_forcing_high_risk`. | Pass |
| FEAT-010-01 | URL and webpage features | Feature extraction remains valid without HTML and returns a model-ready vector. | Verified by `test_feature_extraction_without_html_is_still_valid`. | Pass |
| FEAT-010-02 | Official identity handling | Official domains and configured subdomains for Monash, Google Drive, GitLab, and selected domestic services are recognised. | Verified by official-domain and subdomain regression tests. | Pass |
| FEAT-010-03 | Brand and structural attacks | Brand impersonation, digit substitution, deceptive brand placement, `@` destination obfuscation, and shorteners are identified. | Verified by feature-extraction regression tests. | Pass |
| MODEL-010-01 | Training and inference | Dataset preparation, model comparison, artifact persistence, reload, and prediction complete successfully. | Verified by `test_training_and_prediction_roundtrip`. | Pass |
| MODEL-010-02 | Risk guardrails | Weak signals are capped below High Risk; strong independent signals retain high risk; benign and official patterns are handled separately. | Verified by seven model-guardrail tests. | Pass |
| EXPL-010-01 | Result explanation | Analysis responses include reasons, recommendations, and an explanation mode. Brand explanations name the matched official domain. | Verified by `tests/test_module5_integration.py`. | Pass |
| EXPL-010-02 | Verification status | Analysis response returns a status that distinguishes verified webpages, official identity, URL-only analysis, and failed retrieval. | Verified by pipeline integration tests. | Pass |
| FEEDBACK-010-01 | Employee review workflow | Valid risk reports and result-review requests are stored; conflicting review type and assessment combinations are rejected. | Verified by feedback integration tests. | Pass |
| POLICY-010-01 | Allowlist policy | An active allowlist decision is checked before normal model inference and returns an admin-policy verification result. | Verified by allowlist and temporary-allowlist pipeline tests. | Pass |
| POLICY-010-02 | Blocklist and expiry | Blocklist decisions override normal inference; expired allowlist entries no longer override analysis. | Verified by blocklist and expiry pipeline tests. | Pass |
| POLICY-010-03 | Case lifecycle | Case resolution stores administrator reason and screenshot metadata; policy removal reopens the source case. | Verified by `tests/test_module6_admin.py`. | Pass |
| ADMIN-010-01 | Operational monitoring | Overview data, recorded model metrics, review queues, and scan data are generated from persistent stores. | Verified by administration regression tests. | Pass |
| ADMIN-010-02 | Brand visualiser | Recorded lookalike evidence displays target brand, target domain, and digit-substitution details. | Verified by `test_brand_impersonation_visualiser_returns_character_substitution_evidence`. | Pass |
| ADMIN-010-03 | Documentation route | The technical-documentation PDF asset is available through the expected route. | Verified by `test_technical_documentation_pdf_is_available`. | Pass |
| UI-010-01 | Frontend integration | Current React and TypeScript code compiles into a production Vite bundle. | `npm run build` completed successfully. | Pass |

## Active Model Evaluation Record

The current training report records the following held-out test metrics for the selected XGBoost model:

| Metric | Recorded Value |
| --- | ---: |
| Accuracy | 0.9957002826 |
| Precision | 0.9947271289 |
| Recall | 0.9865341875 |
| F1-score | 0.9906137184 |
| ROC-AUC | 0.9994473979 |
| False-positive rate | 0.0015619509 |
| False-negative rate | 0.0134658125 |
| Average inference time | 0.0013458 ms |

The recorded dataset contains 166,289 cleaned rows, with 116,402 training rows,
16,629 validation rows, and 33,258 held-out test rows. The active model uses 24
features across URL structure, brand identity, sensitive lexical context, and
webpage evidence.

## Persistence Verification

The automated tests exercise the integrated persistence path. The production
application uses separate SQLite stores:

| Data Store | Verified Responsibility |
| --- | --- |
| `data/auth.sqlite3` | users, password hashes, recovery-code hashes, active status, and sessions |
| `data/prediction_logs.sqlite3` | analysed URLs, result category, model version, risk score, and response time |
| `data/clearurl-feedback.sqlite3` | feedback reports, aggregated cases, administrator decisions, evidence metadata, and policy entries |
| `data/model_records.sqlite3` | training reports, model versions, and evaluation metrics |

The test suite confirms that policy decisions affect later scans through the
feedback store before ordinary model inference. It does not treat every employee
report as a confirmed training label; reviewed feedback is prepared separately for
future retraining consideration.

## Browser and Deployment Checks

The production build was executed in this record. The following checks are
environment-dependent and should be completed after each deployment update in a
real browser against the intended public server:

| Check | Reason for Separate Verification | Required Expected Behaviour |
| --- | --- | --- |
| Public URL availability | Depends on ECS instance, Nginx, security group, and backend service state. | The deployed page loads and `/api` calls reach the backend. |
| CAPTCHA image rendering | Requires browser rendering of the returned SVG data URL. | A readable CAPTCHA appears and `New image` returns a replacement challenge. |
| Responsive Admin navigation | Requires real viewport resizing and interaction. | Sidebar/navigation, pagination controls, and Sign out remain reachable on smaller screens. |
| Screenshot file preview | Requires browser file-selection behaviour. | Optional evidence preview and confirmation dialog behave correctly. |
| Live webpage retrieval | Depends on target website, DNS, TLS, remote blocking, and deployment-region network access. | Verification status accurately indicates whether webpage content was retrieved. |

These items are not marked as failed. They are intentionally separated because
this final record did not execute browser automation or a live ECS deployment test.

## Final Assessment

The automated backend regression suite passed completely, and the frontend
production build completed successfully. The tested codebase supports the full
integrated workflow from CAPTCHA-protected authentication through URL analysis,
explanation, employee review, administrator policy decisions, persistent records,
and administration monitoring.

The final release is suitable for demonstration and deployment subject to the
environment-dependent browser and public-server checks listed above.
