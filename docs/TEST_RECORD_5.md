# ClearURL Testing Record #5

## Document Information

- Project: `ClearURL`
- Repository: `url-detection-main`
- Document Type: `Testing Record`
- Language: `English`
- Prepared For: `Project handover, audit trail, and future regression tracking`
- Date: 8.3

## Project Under Test

ClearURL is an explainable phishing URL detection system with:

- an employee-facing frontend for URL analysis and suspicious website reporting
- a backend pipeline covering preprocessing, feature extraction, prediction, explainability, and persistence
- an admin console for scan history, suspicious case review, and model monitoring

## Test Scope Covered In This Record

This record covers the currently integrated version of:

- `Module 1`: Frontend user interface
- `Module 2`: URL validation and preprocessing
- `Module 3`: Feature extraction
- `Module 4`: Detection model training and prediction
- `Module 5`: Explainability and feedback persistence
- `Module 6`: Admin monitoring APIs and dashboard integration
- `Authentication`: Employee and Admin login/session handling

## Test Environment Record

### Backend Environment

- Runtime: `Python 3.10`
- Framework: `Starlette`
- Model serving: local artifact from `artifacts/phishing_detection_model.joblib`

### Frontend Environment

- Runtime: `Node.js`
- Tooling: `Vite`, `React`, `TypeScript`

### Storage Used During Testing

- `data/auth.sqlite3`
- `data/prediction_logs.sqlite3`
- `data/clearurl-feedback.sqlite3`
- `data/model_records.sqlite3`

## Test Accounts Used

- Employee account: `employee@clearurl.local`
- Admin account: `admin@clearurl.local`

## Test Record Summary

### Automated Verification Record

| Record ID | Area                         | Method                      | Date       | Result | Notes                                             |
| --------- | ---------------------------- | --------------------------- | ---------- | ------ | ------------------------------------------------- |
| AUTO-001  | Backend regression suite     | `pytest`                  | 2026-08-03 | Pass   | `16 passed`                                     |
| AUTO-002  | Frontend production build    | `npm run build`           | 2026-08-03 | Pass   | Build completed successfully                      |
| AUTO-003  | Authentication seed accounts | direct backend verification | 2026-08-03 | Pass   | Employee and Admin credentials resolved correctly |

### Integrated Functional Verification Record

| Record ID | Area           | Scenario                                                 | Date       | Result | Notes                                                    |
| --------- | -------------- | -------------------------------------------------------- | ---------- | ------ | -------------------------------------------------------- |
| INT-001   | Employee flow  | Login as Employee and access URL analysis workspace      | 2026-08-03 | Pass   | Employee session and protected analysis access available |
| INT-002   | Employee flow  | Submit URL for analysis and receive backend result       | 2026-08-03 | Pass   | Frontend-backend integration confirmed                   |
| INT-003   | Reporting flow | Submit suspicious website report from Employee workspace | 2026-08-03 | Pass   | Report persisted for admin review                        |
| INT-004   | Admin flow     | Login as Admin and access dashboard                      | 2026-08-03 | Pass   | Admin role validation and protected routes active        |
| INT-005   | Admin flow     | View recent scans and suspicious case list               | 2026-08-03 | Pass   | Admin dashboard connected to live backend data           |
| INT-006   | Admin flow     | View model list and evaluation records                   | 2026-08-03 | Pass   | Module 6 data endpoints available                        |

### Model And Data Validation Record

| Record ID | Area                   | Scenario                                                          | Date       | Result | Notes                                          |
| --------- | ---------------------- | ----------------------------------------------------------------- | ---------- | ------ | ---------------------------------------------- |
| MOD-001   | Model artifact         | Load active production model bundle                               | 2026-08-03 | Pass   | Latest artifact available in`artifacts/`     |
| MOD-002   | Test-set evaluation    | Evaluate current model against PhiUSIIL-based prepared test split | 2026-08-03 | Pass   | Metrics recorded below                         |
| MOD-003   | Hard-negative handling | Validate conservative behavior on known benign URLs               | 2026-08-03 | Pass   | Guardrail and hard-negative integration active |

## Current Baseline Model Record

### Active Recorded Model

- Model name: `xgboost`
- Model version: `xgboost-20260728T083025Z`
- Dataset version: `phiusiil-v4-hard-negatives`

### Baseline Test Metrics

| Metric    | Value                  |
| --------- | ---------------------- |
| Accuracy  | `0.9956992481203008` |
| Precision | `0.9945938818565401` |
| Recall    | `0.9866579463701766` |
| F1-score  | `0.9906100203559`    |
| ROC-AUC   | `0.999041840181793`  |

### Baseline Confusion Matrix

| Actual / Predicted |      Safe | Phishing |
| ------------------ | --------: | -------: |
| Safe               | `25564` |   `41` |
| Phishing           |   `102` | `7543` |

## Current Functional Observations

### Confirmed Working Areas

- Authentication is enforced for employee and admin workflows.
- Employee analysis requests are persisted to prediction logs.
- Employee reports create admin-visible suspicious case records.
- Admin dashboard shows:
  - recent scans
  - suspicious case list
  - risk distribution chart
  - model comparison panel
- Backend data persistence is active across separated SQLite files.

### Important Behavior Notes

- A URL analysis alone creates a scan log record.
- A URL appears in admin suspicious cases only after the employee submits a report.
- Repeated reports for the same URL are aggregated in the admin case view.
- Website HTML fetching may succeed or fail depending on the target site behavior.
- If webpage content is unavailable, model guardrails may reduce the severity of the final displayed result.

## Open Risk Notes

The following items should remain visible in future test records:

- Some live websites may block automated HTML retrieval.
- Production-like model behavior on real-world benign websites should continue to be monitored.
- Additional hard-negative samples may still be needed as new false positives are discovered.
- Admin dashboard should be rechecked whenever a new backend API route is added.

## Test Record Template For Future Entries

Use the following structure for future manual or integrated test logging.

| Record ID | Module / Area | Scenario         | Environment                  | Input / Trigger | Expected Result          | Actual Result     | Status                | Tester | Date       | Notes              |
| --------- | ------------- | ---------------- | ---------------------------- | --------------- | ------------------------ | ----------------- | --------------------- | ------ | ---------- | ------------------ |
| TMP-001   | Example       | Example scenario | Local / Staging / Production | Example input   | Expected system response | Observed response | Pass / Fail / Blocked | Name   | YYYY-MM-DD | Additional remarks |

## Defect Record Template

Use the following structure when a failed result or regression is found.

| Defect ID | Related Record ID | Area    | Severity            | Summary              | Reproduction Context    | Expected Result   | Actual Result   | Status                | Owner | Date Logged |
| --------- | ----------------- | ------- | ------------------- | -------------------- | ----------------------- | ----------------- | --------------- | --------------------- | ----- | ----------- |
| BUG-001   | TMP-001           | Example | High / Medium / Low | Short defect summary | Environment and trigger | Expected behavior | Actual behavior | Open / Fixed / Retest | Name  | YYYY-MM-DD  |

## Sign-off Record

| Reviewer | Role    | Scope Reviewed          | Decision | Date    | Notes   |
| -------- | ------- | ----------------------- | -------- | ------- | ------- |
| Pending  | Pending | Full integrated project | Pending  | Pending | Pending |
