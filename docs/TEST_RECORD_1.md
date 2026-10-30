# ClearURL Test Record #1

## Document Information

- Project: `ClearURL`
- Record type: Pre-completion development baseline
- Purpose: Retrospective record of issues identified before the Iteration 1 release
- Record status: Historical development record, not a new live execution log
- Related iteration: Iteration 1
- Date: 7.24

## Purpose of This Record

This document records the main behaviours that required correction before the first complete version was accepted. It demonstrates how testing and feedback influenced the final integrated prototype.

## Pre-Completion Baseline

| Test ID | Area                               | Earlier behaviour                                                                                                                    | Expected behaviour                                                                          | Development outcome                                        |
| ------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| PRE-001 | Result scoring                     | The user-facing score could be interpreted as a phishing-risk score, where a higher number looked more dangerous                     | A higher displayed score should represent greater safety                                    | Frontend changed to display a safety-oriented score        |
| PRE-002 | Risk classification                | Strong model probability could directly produce High Risk for some benign websites                                                   | High Risk should require stronger supporting evidence                                       | High-risk guardrails were added                            |
| PRE-003 | Web retrieval                      | Analysis could rely mainly on URL structure without consistently using live webpage evidence                                         | The backend should attempt HTML retrieval and redirect inspection before feature extraction | Web retrieval was connected to the analysis pipeline       |
| PRE-004 | Normal website handling            | Some normal sites with missing or unusual webpage metadata received excessive risk                                                   | Missing webpage evidence should not automatically create a severe classification            | Missing-evidence and benign-evidence guardrails were added |
| PRE-005 | Employee to admin flow             | A submitted URL could be analysed without a clear operational record for later review                                                | Analysis records should be persisted and visible to administrators                          | Prediction logging was integrated                          |
| PRE-006 | Suspicious case workflow           | Repeated reports could appear as uncontrolled duplicate entries                                                                      | Repeated reports for the same URL should be aggregated                                      | Case aggregation was implemented                           |
| PRE-007 | Admin display                      | Early dashboard data used repeated placeholder-style entries                                                                         | Each row should represent a different stored scan or case                                   | Dashboard lists were connected to backend data             |
| PRE-008 | Frontend-backend response handling | The frontend could show an invalid-response or unavailable-service message when the response shape did not match its expected fields | The frontend and backend should use a consistent response contract                          | Response normalisation and API error handling were aligned |

## Development Feedback Applied

The pre-completion checks led to the following release changes:

1. The internal phishing risk score was separated from the user-facing safety score.
2. The final displayed score was changed to `100 - risk score`.
3. Webpage retrieval and redirect information were added before feature extraction.
4. Risk guardrails were introduced for missing webpage evidence and strong benign evidence.
5. Prediction logs and report cases were connected to the administrator console.
6. Placeholder-style admin records were replaced with database-backed records.
7. Authentication and role restrictions were applied to employee and admin workflows.

## Remaining Limitations at the Pre-Completion Stage

The following limitations were identified before completion:

- Some websites block automated HTML retrieval.
- The model can still produce uncertain results on unfamiliar benign websites.
- User corrections are not yet automatically used for retraining.
- Employee history and administrator case-status editing are reserved for later iteration work.

## Completion Decision

The pre-completion baseline was not considered ready for the Iteration 1 demonstration until the scoring interpretation, web retrieval flow, data persistence, and administrator display issues had been addressed. The final Iteration 1 record and acceptance document contain the release-level results.
