# ClearURL Test Record #3

## Document Information

- Project: `ClearURL`
- Test area: Scan logging, reporting, case aggregation, and model records
- Record type: Data persistence verification
- Storage design: Separate SQLite databases
- Record status: Iteration 1 evidence
- Date: 7.31

## Test Objective

This record verifies that the system leaves an auditable record after analysis and reporting, while keeping operational data separate from the training dataset.

## Storage Locations

| Database                           | Purpose                       | Main records                                                      |
| ---------------------------------- | ----------------------------- | ----------------------------------------------------------------- |
| `data/auth.sqlite3`              | Authentication and sessions   | Users and active sessions                                         |
| `data/prediction_logs.sqlite3`   | Analysis history              | Request ID, URL, score, category, model, response time, timestamp |
| `data/clearurl-feedback.sqlite3` | Feedback and suspicious cases | Reports, report notes, case status, report counts                 |
| `data/model_records.sqlite3`     | Model monitoring              | Model versions and evaluation records                             |

## Test Cases

| Test ID  | Scenario                                            | Expected persistence result                                                                 | Recorded result                       | Status |
| -------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------- | ------ |
| DATA-001 | Employee completes a valid URL analysis             | A prediction log record is created                                                          | Scan record retained                  | Pass   |
| DATA-002 | Prediction log is inspected                         | The record contains request ID, URL, risk data, model version, response time, and timestamp | Required fields available             | Pass   |
| DATA-003 | Employee submits a suspicious website report        | A report is saved in the feedback database                                                  | Report retained                       | Pass   |
| DATA-004 | Admin opens suspicious cases                        | The submitted report is available as an admin case                                          | Case visible in admin view            | Pass   |
| DATA-005 | Same URL is reported more than once                 | Reports are aggregated into one case with an increased count                                | Repeated reports grouped              | Pass   |
| DATA-006 | New URL is analysed without reporting               | A scan log is created, but no suspicious case is created solely from the scan               | Scan and case records remain separate | Pass   |
| DATA-007 | Admin requests recent scans                         | Records are returned in reverse chronological order                                         | Latest scans shown first              | Pass   |
| DATA-008 | Admin requests model records                        | Model version and evaluation information is retrieved from stored records                   | Model records displayed               | Pass   |
| DATA-009 | Training data directory is inspected after analysis | A normal user analysis does not automatically modify the training dataset                   | Training inputs unchanged by scanning | Pass   |

## Audit Trail

The system records the following information for a completed analysis:

```text
request ID
normalised URL
internal risk score
risk category
phishing probability
model name and version
response time
creation timestamp
```

The system records the following information for a submitted report:

```text
request ID
normalised URL
employee report note
report timestamp
related model version
case status
aggregated report count
```

## Data Separation Rule

Analysing a URL creates an operational scan record. It does not automatically add the URL to the model training dataset. A reported or corrected result can be reviewed later as feedback for future dataset preparation and retraining.

## Conclusion

The persistence design supports traceability without combining authentication, scan logs, feedback, and model records into one database file. This allows administrators to review system activity while keeping future training data preparation under explicit control.
