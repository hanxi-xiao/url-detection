# ClearURL  Test Record #2

## Document Information

- Project: `ClearURL`
- Test area: Authentication, analysis, reporting, and administration APIs
- Record type: Integrated API verification
- Environment: Deployed backend and local backend-compatible request format
- Record status: Completed record for Iteration 1 evidence
- Date: 7.27

## Test Objective

This record verifies that the main backend API workflow operates as one connected service. The tests cover authentication, protected analysis, report submission, administrator access control, and retrieval of monitoring data.

## Test Accounts

- Employee: `employee@clearurl.local`
- Admin: `admin@clearurl.local`

## Test Cases

| Test ID | API area           | Test scenario                                        | Expected result                                                          | Recorded result                       | Status |
| ------- | ------------------ | ---------------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------- | ------ |
| API-001 | Authentication     | Employee submits valid credentials                   | A session token is returned with the employee role                       | Employee session created successfully | Pass   |
| API-002 | Authentication     | Admin submits valid credentials                      | A session token is returned with the admin role                          | Admin session created successfully    | Pass   |
| API-003 | Authentication     | User submits invalid credentials                     | The request is rejected and no session is created                        | Authentication error returned         | Pass   |
| API-004 | Session protection | Unauthenticated user requests session-protected data | The API returns an authentication error                                  | Protected request rejected            | Pass   |
| API-005 | Role protection    | Employee requests an admin endpoint                  | The API rejects the request because the role is insufficient             | Admin endpoint remained protected     | Pass   |
| API-006 | URL analysis       | Authenticated employee submits a valid URL           | The API returns preprocessing, feature, prediction, and explanation data | Complete analysis payload returned    | Pass   |
| API-007 | URL validation     | Employee submits an invalid URL                      | The API returns a validation error                                       | Invalid input rejected                | Pass   |
| API-008 | Reporting          | Employee submits a report for an analysed URL        | The report is accepted and stored for review                             | Report workflow completed             | Pass   |
| API-009 | Admin overview     | Admin requests the overview endpoint                 | Summary metrics and recent case data are returned                        | Overview data returned                | Pass   |
| API-010 | Admin scan history | Admin requests recent scans                          | Recent scan records are returned in reverse chronological order          | Scan records returned                 | Pass   |
| API-011 | Admin cases        | Admin requests suspicious cases                      | Reported cases are returned with status and report count                 | Case records returned                 | Pass   |
| API-012 | Admin model data   | Admin requests model and evaluation records          | Stored model information and evaluation metrics are returned             | Model records returned                | Pass   |

## Integration Trace

The main analysis request follows this path:

```text
Authenticated employee
    -> POST /api/analyze
    -> URL preprocessing
    -> webpage retrieval
    -> feature extraction
    -> trained model prediction
    -> explanation generation
    -> prediction log persistence
    -> JSON response to frontend
```

The report request follows this path:

```text
Employee analysis result
    -> POST /api/reports
    -> report validation
    -> feedback persistence
    -> suspicious case creation or aggregation
    -> admin case retrieval
```

## Evidence

- Backend API routes in `app/api/`
- Authentication implementation in `app/services/auth.py`
- Analysis pipeline in `app/services/pipeline.py`
- Automated tests in `tests/test_auth.py`, `tests/test_pipeline.py`, and `tests/test_module5_integration.py`

## Conclusion

The authenticated employee-to-admin API workflow was integrated successfully for the Iteration 1 prototype. Authentication and role checks prevent unauthorised access, while analysis and reporting results remain available to the relevant administrator views.
