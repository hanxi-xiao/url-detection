# ClearURL M1 Frontend Product and API Handoff

> Project: Explainable AI-Based Phishing URL Detection System
> Module: Module 1 - User Interface Module
> Audience: M2-M5 developers, backend developers, and integration testers
> Document Date: 2026-07-26
> Current Status: Frontend integrated with the live backend

## 1. Purpose

This document describes the implemented frontend behavior and the API contract expected by the employee-facing web interface.
The goal is to let backend and integration teammates connect their modules without changing the frontend business flow.

The frontend is responsible for:

- accepting user input and showing UI states
- sending submitted URLs to the backend
- displaying the safety score, risk category, reasons, and recommendations
- sending suspicious website reports to the backend

The frontend is not responsible for:

- URL normalization and validation logic beyond basic browser checks
- feature extraction
- model prediction
- explainability generation
- report persistence

## 2. Product Scope

The current employee interface is served from `/`.

| Function | Frontend Behavior | Backend Dependency |
| --- | --- | --- |
| URL input | Accept a full web address and run a basic format check | None |
| URL submission | Send the raw URL and show the loading state | `POST /api/analyze` |
| Result display | Show a `0-100` safety score, risk category, and advice | M4, M5 |
| Explanation display | Show simple, non-technical risk reasons | M3, M5 |
| Recommendation display | Show next-step guidance for the employee | M5 |
| Website report | Submit the scan ID, normalized URL, and employee note | `POST /api/reports` |

Supported UI states:

1. idle
2. invalid URL format
3. analysis in progress
4. `Safe` result
5. `Suspicious` result
6. `High Risk` result
7. backend service error
8. report form open
9. report submission success or failure

## 3. Module Data Flow

Recommended high-level flow:

1. The employee enters a URL in the frontend.
2. The frontend sends the raw URL to `POST /api/analyze`.
3. The backend preprocesses the URL through M2.
4. The backend extracts features through M3.
5. The backend predicts phishing risk through M4.
6. The backend builds employee-facing explanations and recommendations through M5.
7. The aggregated result is returned to the frontend in one response.
8. If the employee submits a report, the frontend sends it to `POST /api/reports`.

The frontend should not need to know the internal call order across M2, M3, M4, and M5 as long as the aggregated API response remains stable.

## 4. General API Conventions

### 4.1 Backend Address

The frontend reads the backend base URL from:

```bash
VITE_API_BASE_URL
```

Example:

```bash
VITE_API_BASE_URL=http://localhost:8000
```

The value should not end with `/`.

### 4.2 Data Conventions

- Protocol: HTTP or HTTPS
- Style: REST
- Request body: JSON
- Request header: `Content-Type: application/json`
- Field naming: `camelCase`
- Character encoding: UTF-8

### 4.3 CORS

When frontend and backend run on different origins, the backend must allow the frontend origin.
For local development, allow at least:

```text
http://localhost:5173
http://127.0.0.1:5173
```

Production deployments should allow only the real frontend domain.

## 5. API 1: Analyze URL

### 5.1 Endpoint

- Method: `POST`
- Path: `/api/analyze`

### 5.2 Request Body

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `url` | string | Yes | Full user-entered URL including `http://` or `https://` |

Frontend-side validation only checks:

- the value can be parsed as a URL by the browser
- the protocol is `http:` or `https:`

Formal validation, normalization, and preprocessing remain backend responsibilities.

### 5.3 Recommended Success Response

```json
{
  "requestId": "scan-9f2d69f2f0f64dc0b3b4",
  "frontend": {
    "requestId": "scan-9f2d69f2f0f64dc0b3b4",
    "normalizedUrl": "https://example.com/login",
    "riskScore": 92,
    "safetyScore": 8,
    "riskCategory": "High Risk",
    "reasons": [
      {
        "title": "Login form detected",
        "detail": "This page contains a login form and shares patterns commonly seen in phishing pages."
      }
    ],
    "recommendations": [
      "Do not visit the website or enter any information.",
      "Report the link to your IT or security team."
    ]
  }
}
```

### 5.4 Response Fields Used by the Frontend

| Field | Type | Required | Source | Frontend Use |
| --- | --- | --- | --- | --- |
| `requestId` | string | Recommended | backend/logging | Display scan ID and reuse it in the report API |
| `normalizedUrl` | string | Yes | M2 | Display the final analyzed URL |
| `safetyScore` | number | Recommended | aggregated backend | Display the employee-facing safety score |
| `riskScore` | number | Supported for compatibility | M4 | Internal risk-based score used for compatibility and admin data |
| `riskCategory` | string | Yes | M4 | Control `Safe`, `Suspicious`, or `High Risk` UI styling |
| `reasons` | `RiskFactor[]` | Recommended | M3, M5 | Populate `Why this result?` |
| `recommendations` | `string[]` | Recommended | M5 | Populate `What should I do?` |

`RiskFactor` structure:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `title` | string | Yes | Short employee-friendly factor title |
| `detail` | string | Yes | Plain-language explanation with no advanced model jargon |

### 5.5 Risk Categories

`riskCategory` must be exactly one of:

- `Safe`
- `Suspicious`
- `High Risk`

Displayed interpretation:

| Displayed Score | Category | Suggested User Action |
| --- | --- | --- |
| High safety score | `Safe` | Proceed with normal caution |
| Medium safety score | `Suspicious` | Verify before continuing |
| Low safety score | `High Risk` | Do not visit and report the link |

The backend is the source of truth for the final category.
The frontend should not recalculate the category from the displayed score.

### 5.6 Frontend Response Validation

The frontend currently validates:

- `riskCategory` must be one of the three allowed values
- at least one of `safetyScore` or `riskScore` must exist and be numeric

Fallback behavior:

- if `safetyScore` exists, use it directly
- if only `riskScore` exists, convert it to a displayed safety score by `100 - riskScore`
- if `requestId` is missing, generate a temporary UUID on the client
- if `reasons` is missing, show an empty list
- if `recommendations` is missing, show an empty list

### 5.7 Recommended HTTP Status Codes

| Status | Scenario |
| --- | --- |
| `200` | Analysis completed successfully |
| `400` | Invalid request JSON or malformed URL |
| `422` | URL accepted but preprocessing failed |
| `500` | Internal model or server error |
| `503` | Analysis service temporarily unavailable |

For any non-`2xx` response, the frontend shows a service error message.

## 6. API 2: Report Suspicious Website

### 6.1 Endpoint

- Method: `POST`
- Path: `/api/reports`

### 6.2 Request Body

| Field | Type | Required | Source | Description |
| --- | --- | --- | --- | --- |
| `requestId` | string | Yes | `/api/analyze` response | Link to the original analysis |
| `url` | string | Yes | `normalizedUrl` | The analyzed URL being reported |
| `comment` | string | No | employee input | Optional reason entered by the employee, up to `400` characters |

The frontend does not currently send employee identity in this payload.
If authenticated user identity is required, it should come from the session or token layer rather than from ad hoc request fields.

### 6.3 Recommended Success Response

Any `2xx` response is treated as successful by the current frontend.
Suggested payload:

```json
{
  "status": "accepted",
  "requestId": "scan-9f2d69f2f0f64dc0b3b4",
  "caseId": "case-00128",
  "reportCount": 2
}
```

### 6.4 Recommended HTTP Status Codes

| Status | Scenario |
| --- | --- |
| `201` | New report created |
| `200` | Existing case updated or duplicate report merged |
| `400` | Invalid request body |
| `404` | Matching `requestId` not found |
| `500` | Report persistence failed |

## 7. Reference TypeScript Shapes

```ts
type RiskCategory = "Safe" | "Suspicious" | "High Risk";

type RiskFactor = {
  title: string;
  detail: string;
};

type AnalyzeFrontendPayload = {
  requestId: string;
  normalizedUrl: string;
  safetyScore?: number;
  riskScore?: number;
  riskCategory: RiskCategory;
  reasons: RiskFactor[];
  recommendations: string[];
};

type ReportRequest = {
  requestId: string;
  url: string;
  comment?: string;
};
```

## 8. Integration Checklist

1. Start the backend at the agreed address, for example `http://localhost:8000`.
2. Implement `POST /api/analyze`.
3. Implement `POST /api/reports`.
4. Allow CORS for the frontend origin.
5. Start the frontend and confirm it connects to the real backend.
6. Test all three result categories.
7. Test invalid URLs, backend errors, successful reports, and repeated reports.

## 9. Frontend Regression Test Cases

| Scenario | Input or Backend Behavior | Expected Frontend Result |
| --- | --- | --- |
| Empty input | No URL entered | Show input guidance and do not call the backend |
| Invalid format | `not-a-url` | Show input validation error |
| Unsupported protocol | `ftp://example.com` | Show input validation error |
| Safe result | Backend returns `Safe` | Show green safe state |
| Suspicious result | Backend returns `Suspicious` | Show amber warning state |
| High Risk result | Backend returns `High Risk` | Show red danger state |
| Invalid payload | Missing score and category | Show invalid response error |
| Analyze failure | Backend returns `500` or `503` | Show analysis service unavailable |
| Report success | Backend returns `200` or `201` | Show report submitted |
| Report failure | Backend returns `400` or `500` | Show submission error and allow retry |

## 10. Responsibility Boundary

| Module | Should Provide to M1 | Should Not Be Reimplemented in M1 |
| --- | --- | --- |
| M2 | `normalizedUrl`, preprocessing error states | real URL cleaning and domain parsing |
| M3 | explanation-related feature context | feature extraction logic |
| M4 | `riskScore`, `riskCategory` | model prediction and threshold control |
| M5 | `reasons`, `recommendations`, report persistence result | SHAP logic, recommendation generation, feedback persistence |
| M6 | no direct employee endpoint | admin statistics and model management |

## 11. Notes

- The current system now includes authentication, so report ownership and role separation should rely on the auth layer.
- The employee-facing result page uses a displayed safety score for better usability.
- The backend remains the source of truth for final risk classification.
