# ClearURL M6 Admin Console and API Handoff

> Project: Explainable AI-Based Phishing URL Detection System
> Module: Module 6 - Admin and Model Management Module
> Audience: admin frontend developers, backend developers, M4/M5 developers, and system integration teammates
> Document Date: 2026-07-27
> Current Status: admin console integrated in the shared application

## 1. Purpose

This document defines the data and API contract required by the admin console.
The admin side supports operational monitoring, suspicious case review, and model visibility.

The admin experience should allow authorized staff to:

- inspect recent scans
- review suspicious cases reported by employees
- track case volume and risk distribution
- observe model performance and model versions
- manage future review and retraining workflows

## 2. Product Scope

### 2.1 Core Admin Views

| View | Main Function | Main Endpoint |
| --- | --- | --- |
| Admin Overview | key metrics, risk distribution, summary cards | `GET /api/admin/overview` |
| Suspicious Cases | list aggregated reported cases | `GET /api/admin/cases` |
| Case Detail | inspect reports, metadata, and review notes | `GET /api/admin/cases/{caseId}` |
| Recent Scans | inspect recent scan history | `GET /api/admin/scans` |
| Model Versions | inspect available model versions | `GET /api/admin/models` |
| Model Metrics | inspect evaluation metrics | `GET /api/admin/model/metrics` |
| Evaluation Records | inspect recorded benchmark results | `GET /api/admin/evaluations` |

### 2.2 Iteration 2 and Future Extensions

The following capabilities may be planned even if not fully implemented yet:

- case status update workflow
- admin notes on investigations
- correction labels for false positives and false negatives
- campaign clustering across similar suspicious URLs
- retraining job submission and status tracking
- model activation approval workflow

## 3. Relationship with M1 and M5

The employee frontend creates the upstream data that powers the admin console.

Flow summary:

1. The employee submits a URL in M1.
2. The backend saves a detection log entry.
3. If the employee reports the site, the backend creates or updates a suspicious case through M5.
4. M6 reads aggregated data from prediction logs, case storage, and evaluation records.

Important behavior:

- a scanned URL appears in recent scans even if it is not reported
- a URL appears in suspicious cases only after an employee submits a report
- repeated reports for the same URL are aggregated rather than shown as uncontrolled duplicates

## 4. Security and Access Rules

The admin console must be protected.

Recommended rules:

- unauthenticated requests return `401`
- authenticated non-admin users return `403`
- only admin users can access `/api/admin/*`

The shared application already uses employee and admin roles, so admin endpoints should rely on that role model consistently.

## 5. API 1: Admin Overview

### 5.1 Endpoint

- Method: `GET`
- Path: `/api/admin/overview`

### 5.2 Purpose

Returns the summary information required by the top of the admin dashboard.

### 5.3 Recommended Response Shape

```json
{
  "summary": {
    "totalScans": 1240,
    "safeCount": 980,
    "suspiciousCount": 180,
    "highRiskCount": 80,
    "reportedCount": 54,
    "openCaseCount": 17,
    "averageRiskScore": 41.2,
    "averageResponseMs": 286.4
  },
  "recentCases": [],
  "activeModel": {
    "version": "xgboost-20260728T083025Z",
    "algorithm": "xgboost",
    "createdAt": "2026-07-28T08:30:25Z"
  },
  "evaluationSummary": {
    "total_evaluations": 9,
    "best_model": "xgboost",
    "best_f1_score": 0.9906,
    "best_roc_auc": 0.9990
  }
}
```

## 6. API 2: Suspicious Cases

### 6.1 Endpoint

- Method: `GET`
- Path: `/api/admin/cases`

### 6.2 Purpose

Returns aggregated suspicious cases built from employee reports.

### 6.3 Recommended Query Parameters

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `page` | number | No | Page number |
| `pageSize` | number | No | Items per page |
| `status` | string | No | Filter by case status |
| `riskCategory` | string | No | Filter by `Safe`, `Suspicious`, or `High Risk` |
| `q` | string | No | Search by URL or case ID |

### 6.4 Recommended Case Item Shape

```json
{
  "caseId": "case-00418",
  "requestId": "scan-20260729-102233",
  "url": "https://portal.example.com/login",
  "riskScore": 95,
  "riskCategory": "High Risk",
  "status": "NEW",
  "reportCount": 3,
  "modelVersion": "xgboost-20260728T083025Z",
  "modelVersions": ["xgboost-20260728T083025Z"],
  "lastReportedAt": "2026-07-29T10:24:40Z"
}
```

## 7. API 3: Case Detail

### 7.1 Endpoint

- Method: `GET`
- Path: `/api/admin/cases/{caseId}`

### 7.2 Purpose

Returns the full detail of a suspicious case, including:

- related reports
- model version
- stored comments
- explainability-linked technical details
- optional future admin notes and review labels

## 8. API 4: Recent Scans

### 8.1 Endpoint

- Method: `GET`
- Path: `/api/admin/scans`

### 8.2 Purpose

Returns recent scan history from prediction logs.

### 8.3 Recommended Scan Item Shape

```json
{
  "requestId": "scan-20260729-102233",
  "url": "https://example.com",
  "riskScore": 18,
  "riskCategory": "Safe",
  "modelVersion": "xgboost-20260728T083025Z",
  "responseMs": 214.7,
  "createdAt": "2026-07-29T10:22:33Z"
}
```

Note:

- `riskScore` may remain risk-oriented in storage and backend records
- the employee interface may display a derived safety score instead

## 9. API 5: Model Versions

### 9.1 Endpoint

- Method: `GET`
- Path: `/api/admin/models`

### 9.2 Purpose

Returns the current and historical model versions available for inspection.

### 9.3 Recommended Item Shape

```json
{
  "version": "xgboost-20260728T083025Z",
  "algorithm": "xgboost",
  "status": "active",
  "datasetVersion": "phiusiil-v4-hard-negatives",
  "createdAt": "2026-07-28T08:30:25Z",
  "metrics": {
    "accuracy": 0.9957,
    "precision": 0.9946,
    "recall": 0.9867,
    "f1Score": 0.9906,
    "rocAuc": 0.9990
  }
}
```

## 10. API 6: Model Metrics

### 10.1 Endpoint

- Method: `GET`
- Path: `/api/admin/model/metrics`

### 10.2 Purpose

Returns detailed metrics for the selected model version or for the active model by default.

Recommended metrics:

- accuracy
- precision
- recall
- F1-score
- ROC-AUC
- false positive rate
- false negative rate
- average inference time

## 11. Future Workflow Endpoints

These endpoints may be introduced in later iterations:

- `PATCH /api/admin/cases/{caseId}`
- `POST /api/admin/models/retrain`
- `GET /api/admin/jobs/{jobId}`
- `POST /api/admin/models/{version}/evaluate`
- `POST /api/admin/models/{version}/activate`

They are useful for Iteration 2 planning even if they are not yet fully implemented.

## 12. Admin Dashboard Data Expectations

The admin dashboard should be able to show:

- total scan count
- total reported case count
- total open case count
- average response time
- risk distribution chart
- recent suspicious cases
- recent scan history
- model version list
- evaluation record list

Recent suspicious cases should be ordered by the latest report time, with newest cases first.

## 13. Pagination Pattern

Recommended list response structure:

```json
{
  "items": [],
  "pagination": {
    "page": 1,
    "pageSize": 10,
    "totalItems": 42,
    "totalPages": 5
  }
}
```

## 14. Integration Checklist

1. Protect all `/api/admin/*` routes with admin authorization.
2. Confirm that recent scan data is read from prediction logs.
3. Confirm that suspicious cases come from employee reports aggregated by M5.
4. Confirm newest-first ordering for recent cases and scan history.
5. Confirm model and evaluation records are available in the admin dashboard.
6. Confirm that empty states render correctly when there is no data.

## 15. Admin Test Checklist

| Scenario | Backend Input or State | Expected Result |
| --- | --- | --- |
| Unauthenticated access | no token | return `401` |
| Employee access | non-admin session | return `403` |
| Empty case list | no reported URLs | render empty state without errors |
| Repeated reports | same URL reported multiple times | aggregate into one case and increase `reportCount` |
| Case ordering | new reports arrive | newest case appears first |
| Recent scan history | new analyses occur | newest scan appears first |
| Metrics view | recorded evaluation exists | render model metrics correctly |
| Service failure | backend error `500` or `503` | show recoverable error message |

## 16. Open Coordination Items

Before finalizing a production-like admin workflow, the team should confirm:

1. whether case status values should be `NEW`, `OPEN`, `INVESTIGATING`, and `RESOLVED`
2. whether admin notes are stored in the same database as cases
3. which correction labels may be exported for retraining
4. whether model activation requires a second approver
5. whether future retraining is a real pipeline or a demonstrable prototype flow
6. how long admin-visible reports and notes must be retained
