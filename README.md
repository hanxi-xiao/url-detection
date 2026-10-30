# ClearURL

ClearURL is an explainable AI-based phishing URL detection system for SME employees and security administrators. It provides an authenticated web application that analyses submitted URLs, explains the signals behind each result, records operational activity, accepts employee feedback, and supports administrator-reviewed policy decisions.

The current system includes account registration and recovery-code flows, CAPTCHA verification, verification-status reporting, brand-impersonation detection, explainability based on per-request model contributions, review-case resolution, allowlist and blocklist policies, and paginated administration views.

## Core Capabilities

Employee users can:

- register either an Employee or Admin account through the registration form
- sign in with a CAPTCHA challenge
- change or reset a password using a one-time recovery code and CAPTCHA verification
- submit a complete URL or a domain such as `example.com`; HTTPS is added when a scheme is omitted
- receive a `Safe`, `Suspicious`, or `High Risk` result
- view a verification status, URL-specific reasons, and recommended actions
- submit either a risk report or a request to review a possible model misclassification

Administrator users can:

- access a role-protected administration console with sidebar navigation
- view overview metrics, risk distribution, scan outcome mix, and recorded model comparisons
- filter and paginate review cases, scan records, policy entries, brand-impersonation evidence, and accounts
- resolve a review case through a confirmation workflow with a mandatory decision reason and optional screenshot evidence
- create persistent blocklist entries or permanent/time-limited allowlist entries
- remove a policy entry when it is no longer appropriate
- suspend active employee accounts without deleting their historical records
- review held-out model metrics, operational feedback signals, and recorded model versions

## Architecture

The application is delivered as a React + TypeScript frontend and a Python Starlette backend. The backend coordinates the full analysis path:

```text
Authenticated URL submission
  -> URL validation and normalisation
  -> live webpage and redirect retrieval when available
  -> lexical, identity, and webpage feature extraction
  -> XGBoost model inference and risk guardrails
  -> local feature-contribution explanation
  -> verification status and employee recommendations
  -> prediction logging and optional review workflow
```

The backend stores operational data in separate SQLite databases under `data/`:

- `auth.sqlite3`: users, password hashes, roles, account status, and sessions
- `prediction_logs.sqlite3`: analysis history and response timing
- `clearurl-feedback.sqlite3`: employee reports, review cases, decisions, screenshot metadata, and policy entries
- `model_records.sqlite3`: model versions, training metadata, and evaluation records

## Project Structure

- `src/`: React frontend, employee workflow, authentication screens, and administration console
- `app/api/`: HTTP routes for authentication, URL analysis, reports, and administration
- `app/services/`: authentication, analysis orchestration, webpage retrieval, and shared application state
- `app/module2/`: URL validation, default HTTPS handling, and normalisation
- `app/module3/`: URL, brand identity, redirect, and webpage feature extraction
- `app/module4/`: dataset preparation, model training, prediction, thresholds, and model guardrails
- `app/module5/`: feature-impact explanations, recommendations, feedback persistence, and policy lookup
- `app/module6/`: logs, model records, retraining-data preparation, administrative aggregations, and pagination
- `artifacts/`: trained model bundle, comparison output, and training report
- `data/`: local SQLite operational data
- `examples/`: prepared PhiUSIIL features and additional contextual training samples
- `tests/`: automated backend regression tests
- `docs/`: user stories, acceptance criteria, test records, run sheet, and technical documentation

## Hosted Access

The currently configured deployed access URL is:

```text
http://120.26.118.110/
```

The hosted environment depends on the server, reverse-proxy, model artifact, and SQLite files being available. If the server cannot retrieve external webpages, the application still performs URL-only analysis and displays a verification-status message explaining that limitation.

## Local Setup

### Requirements

- Node.js `>= 22`
- Python `3.10+` recommended
- Conda environment `torch3.10` is supported by the project workflow

### 1. Start the backend

From the repository root:

```bash

python -m pip install -r requirements-backend.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The backend is available at:

```text
http://127.0.0.1:8000
```

### 2. Start the frontend

Open a second terminal in the repository root:

```bash
npm install
npm run dev
```

Vite normally serves the frontend at:

```text
http://127.0.0.1:5173
```

During local development, frontend requests to `/api/*` are proxied to `http://127.0.0.1:8000`.

## Authentication

The seeded local demonstration accounts are:

| Role     | Email                       | Password        | Recovery Code                  |
| -------- | --------------------------- | --------------- | ------------------------------ |
| Employee | `employee@clearurl.local` | `employee123` | `CLEARURL-EMPLOYEE-RECOVERY` |
| Admin    | `admin@clearurl.local`    | `admin123`    | `CLEARURL-ADMIN-RECOVERY`    |

CAPTCHA verification is required for sign-in, registration, password changes, and password resets. New accounts receive a recovery code once after registration. The user must save that code because it is required together with CAPTCHA verification for later password recovery.

Passwords are stored as PBKDF2-SHA256 hashes. The system stores only the hash of a recovery code, not the displayed code itself.

## URL Analysis and Explainability

The active model artifact is:

```text
artifacts/phishing_detection_model.joblib
```

The currently recorded training report is:

```text
artifacts/training_report.json
```

The model compares Logistic Regression, Random Forest, and XGBoost during training. The active artifact is XGBoost, selected using validation precision. Its prepared held-out test metrics are recorded in `training_report.json`.

The feature schema currently contains 24 model features covering:

- URL structure: length, domain length, special characters, IP domains, subdomain depth, HTTPS, and suspicious lexical patterns
- brand and identity signals: similarity to monitored brands, character substitutions, known official domains/subdomains, deceptive brand placement, `@` destination obfuscation, and shortening services
- sensitive context: security-related keywords and unusually long sensitive paths
- webpage evidence: login forms, password fields, external form submission, iframes, page title/domain consistency, and title overlap

When the active XGBoost bundle supports it, ClearURL obtains per-request tree contribution values using XGBoost `pred_contribs`. The explanation layer combines those local contributions with the extracted evidence and returns only reasons relevant to the submitted URL. If local contributions are unavailable, the API identifies the fallback explanation mode.

The result also includes a verification status:

- `Webpage content verified`: HTML content was retrieved and included in analysis
- `Official domain recognised`: a configured official identity was recognised but full HTML was unavailable
- `Short-link destination not verified`: a shortening service was detected without a verified destination
- `Destination could not be verified` or `Webpage access failed`: live retrieval could not be completed
- `URL-only analysis`: the result is based on structural and identity signals only

The API calculates a safety score as the inverse of the backend risk score: a higher safety score means lower detected risk. The current employee result view deliberately does not display a numeric score; it shows the risk category, verification status, URL-specific reasons, and recommended actions. Safety scores remain available for administrator scan filtering and brand-visualisation records.

## Policy Decisions

Before model inference, the pipeline checks for a reviewed policy entry:

- an `allowlist` match returns a Safe result and records that an administrator decision overrode model inference
- a `blocklist` match returns a High Risk result and records the same override provenance
- allowlist entries may be permanent or time-limited; blocklist entries are persistent until an administrator removes them

Policy decisions are operational overrides. They do not automatically alter the trained model or its held-out evaluation metrics. Reviewed feedback can be prepared for later retraining through the administration API.

## Retraining

Prepared training inputs include:

- `examples/phiusiil_model_features.csv`
- `examples/hard_negative_safe_samples.csv`
- `examples/official_safe_sites.csv`
- `examples/brand_impersonation_samples.csv`
- `examples/acceptance_context_samples.csv`

Run the current retraining workflow with:

```bash
conda run -n torch3.10 python -m app.module4.train \
  --data examples/phiusiil_model_features.csv \
  --extra-data examples/hard_negative_safe_samples.csv \
  --extra-data examples/official_safe_sites.csv \
  --extra-data examples/brand_impersonation_samples.csv \
  --extra-data examples/acceptance_context_samples.csv \
  --output-dir artifacts \
  --selection-metric precision \
  --dataset-version phiusiil-v9-official-domain-guardrails
```

This command updates the model bundle, `model_comparison.csv`, `training_report.json`, and the model-record database used by the administration console.

## API Routes

### Authentication

- `GET /api/auth/captcha`
- `POST /api/auth/login`
- `POST /api/auth/register`
- `POST /api/auth/change-password`
- `POST /api/auth/reset-password`
- `GET /api/auth/session`
- `POST /api/auth/logout`

### Employee Analysis and Feedback

- `POST /api/analyze`
- `POST /api/reports`

### Administration

- `GET /api/admin/overview`
- `GET /api/admin/users`
- `PATCH /api/admin/users/{user_id}/status`
- `GET /api/admin/cases`
- `POST /api/admin/cases/action`
- `GET /api/admin/scans`
- `GET /api/admin/models`
- `GET /api/admin/model/metrics`
- `GET /api/admin/evaluations`
- `GET /api/admin/feedback-dataset`
- `GET /api/admin/policy-entries`
- `DELETE /api/admin/policy-entries/{entry_id}`
- `GET /api/admin/brand-impersonation`
- `GET /api/admin/review-insights`

All administration routes require an authenticated Admin session. List routes use query parameters for filtering and pagination.

## Tests

Run backend regression tests:

```bash
conda activate torch3.10
pytest -q
```

Run the frontend production build:

```bash
npm run build
```

The automated tests cover URL preprocessing, training behaviour, end-to-end pipeline responses, explainability integration, authentication and recovery-code flows, documentation routing, and administration APIs.

## Documentation

- [Iteration 1 User Stories](docs/ITERATION1_USER_STORIES.md)
- [Iteration 2 User Stories](docs/ITERATION2_USER_STORIES.md)
- [Iteration 1 Acceptance Criteria](docs/ITERATION1_ACCEPTANCE_CRITERIA.md)
- [Model Test Results](docs/MODEL_TEST_RESULTS.md)
- [Test Record 9](docs/TEST_RECORD_9.md)
- [Final System Test Record](docs/TEST_RECORD_10_FINAL.md)
- [GitLab Upload Plan](docs/GITLAB_UPLOAD_PLAN.md)
- [Technical Documentation PDF](<docs/Technical%20Documentation.pdf>)
- [Iteration 1 Run Sheet PDF](docs/FIT5238_Group15_Iteration1_Run_Sheet.pdf)

## Operational Notes

- Some sites block automated retrieval or are inaccessible from a deployment environment. The verification status must be considered alongside the risk category.
- A failed DNS lookup or inaccessible webpage is not, by itself, treated as proof of phishing.
- Brand similarity and deceptive brand placement are risk indicators, not legal confirmation that a website is malicious.
- Do not commit `.env` files, access tokens, private keys, or real user credentials. Generated directories such as `node_modules/`, `dist/`, caches, and local system files are excluded by `.gitignore`.

## AI Assistance Declaration

We acknowledge the use of OpenAI ChatGPT during the development and preparation of this project. The tool assisted with reviewing code integration across system components, identifying frontend-backend communication issues, analysing testing bugs, and suggesting improvements to API responses, score interpretation, data persistence, and documentation. All implementation decisions, code review, testing, validation, and final edits were completed and verified by the project team.
