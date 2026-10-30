# ClearURL M5 Explainability and Feedback API Handoff

> Project: Explainable AI-Based Phishing URL Detection System
> Module: Module 5 - Explainability and Feedback Module
> Audience: M1 frontend, M2-M4 backend, M6 admin module, and system integration team
> Document Date: 2026-07-27
> Current Status: Integrated into the shared backend

## 1. Purpose

This document defines the interface and responsibility boundary for Module 5.
M5 converts model output into employee-friendly explanations and handles suspicious website report persistence for later admin review.

M5 is responsible for:

- building explanation reasons from model features and feature importance signals
- converting technical indicators into plain-language employee messages
- generating risk-aware employee recommendations
- accepting suspicious website reports
- deduplicating repeated reports and aggregating reviewable cases

M5 is not responsible for:

- URL validation and normalization
- feature extraction
- model training, phishing probability, or final risk classification
- employee-facing page rendering
- admin review workflow or model retraining orchestration

## 2. System Data Flow

Recommended integrated flow:

1. M2 preprocesses the submitted URL.
2. M3 extracts URL and webpage features.
3. M4 predicts phishing probability and final risk category.
4. M5 receives the prediction context and feature impacts.
5. M5 returns employee-facing reasons and recommendations.
6. The aggregated backend sends a single response to `/api/analyze`.
7. When the employee submits a report, M5 validates and persists it through `/api/reports`.

M5 does not require the frontend to call a separate explainability endpoint.

## 3. Stable Employee-Facing APIs

The team should keep these employee-facing endpoints stable:

- `POST /api/analyze`
- `POST /api/reports`

Within `/api/analyze`, M5 owns the generation of:

- `reasons`
- `recommendations`

Within `/api/reports`, M5 owns:

- validation against stored analysis records
- report persistence
- case aggregation and deduplication

## 4. Shared Data Conventions

### 4.1 Risk Category

M5 does not recalculate the final category.
`riskScore` and `riskCategory` come from M4.

Allowed values:

- `Safe`
- `Suspicious`
- `High Risk`

### 4.2 Time Format

All timestamps should use UTC ISO 8601, for example:

```text
2026-07-27T10:21:42Z
```

### 4.3 Identifiers

| Field | Example | Issued By |
| --- | --- | --- |
| `requestId` | `scan-20260727-001842` | aggregated backend |
| `caseId` | `case-00418` | feedback persistence layer |
| `reportId` | `report-a8d18c4f` | feedback persistence layer |

Identifiers must be treated as opaque strings.

## 5. PredictionContext Provided to M5

M5 expects a complete prediction context after M4 finishes prediction.

### 5.1 Structure

```json
{
  "requestId": "scan-20260727-001842",
  "normalizedUrl": "https://example.com/login",
  "modelVersion": "xgboost-20260728T083025Z",
  "featureSchemaVersion": "clearurl-m3-v1",
  "features": {
    "URLLength": 31,
    "HasLoginForm": 1,
    "DomainTitleMatch": 0
  },
  "phishingProbability": 0.9732,
  "riskScore": 96.4,
  "riskCategory": "High Risk"
}
```

### 5.2 Field Description

| Field | Type | Required | Source | Description |
| --- | --- | --- | --- | --- |
| `requestId` | string | Yes | aggregated backend | Links analysis, logging, and reports |
| `normalizedUrl` | string | Yes | M2 | Standardized URL |
| `modelVersion` | string | Yes | M4 | Model version used for the prediction |
| `featureSchemaVersion` | string | Yes | M3/M4 | Feature definition version |
| `features` | object | Yes | M3 | Feature name to numeric value mapping |
| `phishingProbability` | number | Yes | M4 | `0-1` phishing probability |
| `riskScore` | number | Yes | M4 | internal `0-100` risk-oriented score |
| `riskCategory` | string | Yes | M4 | Final category for the user-facing result |

The `features` field must be name-based rather than a raw unnamed numeric array.

## 6. Explanation Service Contract

### 6.1 Preferred Same-Process Interface

If all modules run in one Python backend, prefer direct function calls such as:

```python
explanation = m5_service.process_prediction(context, feature_impacts)
```

### 6.2 Optional Internal HTTP Endpoint

Only if modules are deployed separately, an internal endpoint may be used:

- `POST /api/internal/explanations`

This endpoint should not be exposed directly to employee browsers.

### 6.3 Explanation Reason Shape

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `feature` | string | Yes | Technical feature name for logs and admin review |
| `value` | number/string/null | Yes | Actual feature value |
| `impact` | number | Yes | Relative impact magnitude |
| `direction` | string | Yes | `increases_risk` or `decreases_risk` |
| `title` | string | Yes | Plain-language short reason title |
| `detail` | string | Yes | Employee-facing explanation |

The employee-facing frontend should only receive:

```json
[
  {
    "title": "Login form detected",
    "detail": "This page contains a login form and shares patterns often seen in deceptive websites."
  }
]
```

### 6.4 Implementation Guidance

- Prefer deterministic explanation generation over free-form generative output.
- Keep employee-facing reasons short and understandable.
- Return only the most meaningful reasons, usually `2-3`.
- Avoid exposing raw model jargon such as SHAP internals to employees.
- Keep ordering stable for identical model and feature inputs.

## 7. Recommendation Generation Rules

Recommendations should be deterministic and tied to the final category.

Suggested behavior:

- `Safe`: continue with normal caution, do not over-promise absolute safety
- `Suspicious`: recommend verification through official channels
- `High Risk`: recommend not visiting the site and reporting it immediately

M5 may add one context-specific recommendation if it is clearly relevant and not repetitive.

## 8. API: Report Suspicious Website

### 8.1 Request

- Method: `POST`
- Path: `/api/reports`

Request body:

```json
{
  "requestId": "scan-20260727-001842",
  "url": "https://example.com/login",
  "comment": "The site appeared in an unexpected invoice email."
}
```

### 8.2 Request Validation Rules

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `requestId` | string | Yes | Must match an existing stored analysis |
| `url` | string | Yes | Must match the normalized URL of that analysis |
| `comment` | string | No | Optional employee note, maximum `400` characters after trimming |

M5 must obtain trusted prediction data from stored analysis logs rather than trusting any prediction fields sent by the client.

### 8.3 Recommended Success Responses

New report created:

```json
{
  "status": "created",
  "caseId": "case-00418",
  "reportId": "report-a8d18c4f",
  "reportCount": 1
}
```

Existing case reused or duplicate retried:

```json
{
  "status": "merged",
  "caseId": "case-00418",
  "reportId": "report-a8d18c4f",
  "reportCount": 2
}
```

### 8.4 Deduplication and Idempotency

Recommended rules:

1. Case merge key: `normalizedUrlHash + modelVersion`
2. Report idempotency key: `requestId + normalizedUrlHash`

Recommended behavior:

| Scenario | Behavior | `reportCount` |
| --- | --- | --- |
| First report for URL and model version | Create case and report | Set to `1` |
| Same `requestId` retried | Return the original report | Do not increase |
| Same URL and model version, new `requestId` | Merge into existing case and add a report | Increase by `1` |
| Same URL but different model version | Create a new case | New case starts at `1` |
| URL does not match the stored analysis record | Reject the request | No change |

### 8.5 Recommended Status Codes

| Status | Scenario |
| --- | --- |
| `201` | New report created |
| `200` | Duplicate retry or merged report |
| `400` | Invalid payload or note too long |
| `404` | `requestId` not found |
| `409` | URL does not match the stored analysis |
| `500` | Report persistence failure |

## 9. Persistence and Admin Handoff

Recommended logical storage:

1. analysis log table
2. suspicious case table
3. case report table

Important handoff rules for M6:

- M6 reads aggregated `reportCount` values from suspicious cases
- M6 can inspect retained employee notes
- employee reports indicate suspicion, not ground-truth phishing labels
- only reviewed admin labels such as `PHISHING` or `LEGITIMATE` should be exported into future training datasets

## 10. Reference TypeScript Shapes

```ts
type PredictionContext = {
  requestId: string;
  normalizedUrl: string;
  modelVersion: string;
  featureSchemaVersion: string;
  features: Record<string, number>;
  phishingProbability: number;
  riskScore: number;
  riskCategory: "Safe" | "Suspicious" | "High Risk";
};

type EmployeeReason = {
  title: string;
  detail: string;
};

type ReportRequest = {
  requestId: string;
  url: string;
  comment?: string;
};
```

## 11. Integration and Test Checklist

| Scenario | Input or State | Expected Result |
| --- | --- | --- |
| High Risk explanation | strong positive phishing indicators | return `2-3` strong employee-facing reasons |
| Safe explanation | mostly benign indicators | return cautious wording without promising certainty |
| Feature order changes | JSON key order differs | use named fields and keep output stable |
| Feature schema mismatch | schema differs from model metadata | reject explanation generation |
| No strong reasons | weak or missing usable evidence | return a safe generic explanation |
| Safe/Suspicious/High Risk advice | final category varies | return matching, non-contradictory recommendations |
| First report | new URL and model version | return `201`, `reportCount = 1` |
| Browser retry | same request repeated | return `200`, no duplicate report |
| Repeated URL report | new request, same URL and model version | merge into existing case |
| Tampered URL | URL mismatches stored analysis | return `409` |
| Admin detail view | M6 requests case data | expose technical explanation data for admin-only views |

## 12. Open Coordination Items

Before final production deployment, the team should confirm:

1. the final model family used by M4
2. the artifact directory and version naming convention
3. the exact `featureSchemaVersion` and full feature list
4. the phishing class index used by the model
5. the final risk thresholds
6. whether M5 and M6 share a database or use linked data stores
7. how long employee reports and admin notes should be retained
8. which reviewed statuses are exportable into future training data
