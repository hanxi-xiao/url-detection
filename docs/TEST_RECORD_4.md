# ClearURL Test Record #4

## Document Information

- Project: `ClearURL`
- Test area: Browser-based employee and administrator workflows
- Record type: User acceptance test record
- Target audience: SME employees and security administrators
- Record status: Iteration 1 acceptance evidence
- Date: 8.1

## Test Objective

This record verifies that a user can complete the intended workflows through the deployed frontend without directly interacting with backend endpoints.

## User Acceptance Scenarios

| Test ID | User role | Scenario                            | Expected result                                                                   | Recorded result               | Status |
| ------- | --------- | ----------------------------------- | --------------------------------------------------------------------------------- | ----------------------------- | ------ |
| UAT-001 | Visitor   | Open the deployed application       | The landing and login interface loads                                             | Login interface displayed     | Pass   |
| UAT-002 | Employee  | Select the Employee role            | The employee login form is shown                                                  | Employee role selected        | Pass   |
| UAT-003 | Employee  | Sign in with valid credentials      | The employee analysis workspace opens                                             | Employee workspace displayed  | Pass   |
| UAT-004 | Employee  | Sign in with invalid credentials    | An error is displayed and access is denied                                        | Error displayed               | Pass   |
| UAT-005 | Employee  | Submit an incomplete or invalid URL | The input is rejected with a readable message                                     | Validation feedback displayed | Pass   |
| UAT-006 | Employee  | Submit a valid URL                  | An analysis progress state is shown before the result                             | Progress state displayed      | Pass   |
| UAT-007 | Employee  | Review a completed result           | The page shows the URL, safety score, risk category, reasons, and recommendations | Result information displayed  | Pass   |
| UAT-008 | Employee  | Submit a suspicious website report  | The report form accepts an optional note and confirms submission                  | Report confirmation displayed | Pass   |
| UAT-009 | Employee  | Sign out                            | The session is cleared and the login screen returns                               | User returned to login        | Pass   |
| UAT-010 | Admin     | Select the Admin role and sign in   | The operations dashboard opens                                                    | Admin console displayed       | Pass   |
| UAT-011 | Admin     | Review risk distribution            | Safe, Suspicious, and High Risk scan counts are displayed                         | Risk chart displayed          | Pass   |
| UAT-012 | Admin     | Review recent suspicious cases      | Reported URLs, categories, report counts, and statuses are displayed              | Case queue displayed          | Pass   |
| UAT-013 | Admin     | Review all recent scans             | Recent scans show URL, category, score, model version, and response time          | Scan history displayed        | Pass   |
| UAT-014 | Admin     | Review model records                | Model versions and evaluation records are displayed                               | Model panels displayed        | Pass   |

## User-Facing Result Rules

The frontend presents the model output using a safety-oriented score:

- Higher score: the link appears safer
- Medium score: the user should verify the link
- Lower score: the link is more dangerous

The visible risk categories are:

- `Safe`
- `Suspicious`
- `High Risk`

Each completed result also provides readable explanations and recommended actions rather than showing only a numerical prediction.

## Usability Observations

- The employee workflow is focused on one primary action: submit a URL for analysis.
- The result page keeps the score, category, explanations, and recommendations together.
- The report action is available after the analysis result is displayed.
- The administrator workflow separates summary charts from detailed scan and case lists.
- Role selection prevents the employee and administrator workflows from being mixed together.

## Known Boundary

The browser workflow depends on the backend being available. If a target website blocks automated retrieval, the result may contain less webpage evidence, but the URL analysis flow remains available.

## Conclusion

The main employee and administrator acceptance scenarios are supported by the deployed frontend. The frontend provides a complete user-facing path from authentication to analysis, reporting, and administrative review.
