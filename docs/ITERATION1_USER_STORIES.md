# ClearURL Iteration 1 User Stories

## Feature `Authentication and Role-Based Access`

### User Story 1: Employee Login

**US 1 As an employee, I want to sign in with my employee account so that I can access the phishing URL analysis workspace.**

**Acceptance Criteria**

1. Given a user has no active session, when they open ClearURL, then the authentication page is displayed before any Employee analysis function is available.
2. Given the authentication page is displayed, when the user selects the `Employee` role, then the interface identifies that the next login attempt is for the Employee workspace.
3. Given the user enters an email address and password, when they submit the Employee login form, then the backend validates the credentials against the authentication database.
4. Given the submitted credentials belong to an active Employee account, when validation succeeds, then the backend creates an authenticated session and returns the Employee role with the session response.
5. Given the frontend receives a successful Employee session, when it stores the session, then it opens the Employee URL analysis workspace.
6. Given the email address or password is incorrect, when validation fails, then the system displays an authentication error and does not create a session.
7. Given an unauthenticated visitor attempts to call the URL analysis API, when the backend receives the request without a valid bearer token, then it rejects the request and does not run the analysis pipeline.
8. Given an Employee is signed in, when they use the system, then they can access Employee-facing URL analysis and report functions but cannot access Admin-only data.

**List**

- Add an employee login entry on the main landing page.
- Validate employee credentials against the authentication database.
- Redirect the employee to the URL analysis workspace after successful login.
- Display an error message for invalid login attempts.

### User Story 2: Admin Login

**US 2 As an admin, I want to sign in with my admin account so that I can access the administrative monitoring dashboard.**

**Acceptance Criteria**

1. Given the authentication page is displayed, when the user selects the `Admin` role, then the interface identifies that the next login attempt is for the Admin workspace.
2. Given the user enters an email address and password, when they submit the Admin login form, then the backend validates the credentials and retrieves the stored account role.
3. Given the submitted credentials belong to an active Admin account, when validation succeeds, then the backend creates an authenticated Admin session.
4. Given the frontend receives a successful Admin session, when it stores the session, then it opens the administrative monitoring dashboard rather than the Employee workspace.
5. Given an Employee account is used while `Admin` is selected, when authentication returns the Employee role, then the frontend displays an error and does not open the Admin dashboard.
6. Given invalid credentials are submitted, when authentication fails, then the system displays an error message and does not reveal whether the email address exists.
7. Given an authenticated Employee calls an `/api/admin/*` endpoint, when the backend checks the session role, then it returns a permission error and does not return Admin data.
8. Given an Admin signs out, when the logout action is completed, then the backend session is deleted and the frontend returns to the unauthenticated landing page.

**List**

- Add an admin login entry on the main landing page.
- Validate admin credentials against the authentication database.
- Restrict access to `/api/admin/*` endpoints to authenticated admin users only.
- Display an authentication or permission error when access is denied.

## Feature `URL Submission and Analysis`

### User Story 3: Submit URL for Analysis

**US 3 As an employee, I want to submit a URL for analysis so that I can know whether the website is safe, suspicious, or high risk.**

**Acceptance Criteria**

1. Given an authenticated Employee opens the analysis workspace, when the page loads, then a URL input field and an `Analyse URL` action are available.
2. Given the Employee enters a web address, when the form is submitted, then the frontend validates that the address can be interpreted as an `http://` or `https://` URL.
3. Given the entered value is empty, malformed, or uses an unsupported protocol, when the Employee submits the form, then the frontend displays a clear input error and does not call the analysis API.
4. Given the entered URL is valid, when the Employee selects `Analyse URL`, then the frontend sends the URL and the authenticated bearer token to the backend analysis API.
5. Given the backend receives a valid authenticated analysis request, when preprocessing starts, then it normalizes the URL and prepares it for feature extraction.
6. Given feature extraction and prediction complete, when the backend returns its response, then the response includes a normalized URL, risk result, safety score, explanation data, and recommendations.
7. Given the request is being processed, when the frontend waits for the API response, then it displays an analysis-in-progress state and disables duplicate submission.
8. Given the backend is unavailable or returns an invalid response, when the request fails, then the frontend displays an understandable service error instead of presenting an incomplete result.

**List**

- Provide a URL input field in the employee analysis workspace.
- Validate the URL format before submission.
- Send valid URLs to the backend analysis API.
- Display the returned risk score and classification result.

### User Story 4: View Analysis Result

**US 4 As an employee, I want to view the phishing detection result clearly so that I can understand the level of risk before visiting the website.**

**Acceptance Criteria**

1. Given the backend completes a URL analysis successfully, when the response reaches the frontend, then the result area changes from its empty or loading state to an analysis-complete state.
2. Given a result is displayed, when the Employee reads the outcome, then the normalized URL returned by the backend is shown so the user can confirm the analysed address.
3. Given the backend provides a safety score, when the result is rendered, then the score is displayed on a `0` to `100` scale where a higher score indicates a safer URL.
4. Given the backend returns a risk category, when the result is rendered, then it displays exactly one of `Safe`, `Suspicious`, or `High Risk`.
5. Given the risk category is `Safe`, `Suspicious`, or `High Risk`, when it is displayed, then the result uses visually distinct colour treatment so the categories can be differentiated quickly.
6. Given webpage verification information is available, when the result is displayed, then the verification status and its explanatory detail are shown separately from the risk category.
7. Given no result has been submitted yet, when the Employee views the result panel, then the interface explains that detection output will appear after a URL is analysed.
8. Given the result is shown, when the Employee needs to report it, then the report action remains available from the completed result.

**List**

- Display the analysed URL after the request is completed.
- Display the safety score from the backend result.
- Display the corresponding risk category.
- Use clear colour-coded UI feedback for Safe, Suspicious, and High Risk.

## Feature `Explainability and Recommendation Display`

### User Story 5: View Risk Explanations

**US 5 As an employee, I want to see the reasons behind the prediction so that I can understand why a URL is considered risky.**

**Acceptance Criteria**

1. Given a completed analysis includes explanation data, when the result is displayed, then the Employee can see a dedicated `Why this result?` section.
2. Given the backend returns one or more explanation items, when the section is rendered, then each item displays a concise title and a readable supporting description.
3. Given the explanation is based on a detected URL, domain, webpage, redirect, or policy signal, when it is shown to the Employee, then the wording reflects the observed factor rather than exposing raw feature-vector values.
4. Given multiple applicable factors are returned, when the result is displayed, then the factors are presented as separate list items rather than combined into one unreadable message.
5. Given no specific explanation factor is available, when the backend supplies a fallback explanation, then the Employee receives a clear combined-risk message instead of an empty explanation area.
6. Given the result is `Safe`, when low-risk evidence is available, then the explanation can communicate the relevant reassuring signal without representing the result as a guarantee of safety.
7. Given the Employee views the explanation, when they compare it with the risk category, then the explanation remains visible on the same completed-result screen.

**List**

- Display backend-provided phishing explanation messages.
- Present explanations as readable risk factors.
- Show explanations alongside the risk score and classification.

### User Story 6: View Recommended Actions

**US 6 As an employee, I want to see recommended actions after analysis so that I know what to do next when a link appears risky.**

**Acceptance Criteria**

1. Given a URL analysis result is displayed, when the Employee views the completed result, then a dedicated `What should I do?` recommendation section is shown.
2. Given the risk category is `Safe`, when recommendations are selected, then the system provides normal-caution guidance rather than instructing the user to report the site as malicious.
3. Given the risk category is `Suspicious`, when recommendations are selected, then the system advises the Employee to verify the domain and avoid entering sensitive information until it is trusted.
4. Given the risk category is `High Risk`, when recommendations are selected, then the system advises the Employee not to visit the site or enter credentials.
5. Given recommendations are displayed, when the Employee reads them, then they are written as short, ordered, non-technical action items.
6. Given the analysis result is visible, when the Employee reviews recommendations, then the recommendations remain presented with the risk category and explanations so that the advice has context.
7. Given the Employee disagrees with the outcome after reading the advice, when they choose to report the website, then the reporting action is available from the same result screen.

**List**

- Display backend-provided recommendations in the result page.
- Present recommendations as a short ordered list.
- Keep the recommendations visible together with the risk classification.

## Feature `Suspicious Website Reporting`

### User Story 7: Report a Suspicious Website

**US 7 As an employee, I want to report a suspicious website after analysis so that the case can be reviewed by an administrator.**

**Acceptance Criteria**

1. Given an authenticated Employee has received a completed analysis result, when they select `Report this website`, then the system opens a reporting form linked to that result.
2. Given the reporting form is open, when the Employee enters a note, then the note is optional and is retained while the form remains open.
3. Given the Employee submits a report, when the request is sent to the backend, then it includes the scan request ID, normalized URL, and the Employee's optional comment.
4. Given the backend accepts the report, when persistence succeeds, then the frontend displays a confirmation state and prevents immediate duplicate submission from the same result.
5. Given the backend cannot store the report, when the request fails, then the frontend displays an error message and leaves the reporting form available for another attempt.
6. Given a report is accepted, when the backend stores it, then the report is associated with the analysed URL and is available for Administrator review.
7. Given an unauthenticated visitor attempts to submit a report, when the backend receives the request without a valid session, then it rejects the request and does not create a case record.

**List**

- Provide a report button on the analysis result page.
- Allow the employee to add an optional suspicious activity note.
- Submit report details to the backend reporting API.
- Display a success message after report submission.

## Feature `Prediction Logging and Data Recording`

### User Story 8: Record Scan History

**US 8 As a system maintainer, I want every analysed URL to be recorded in the prediction log so that system activity can be monitored later.**

**Acceptance Criteria**

1. Given an authenticated analysis request completes successfully, when the backend produces the final result, then it creates a prediction-log record.
2. Given a prediction-log record is created, when it is stored, then it includes the request ID, normalized URL, internal risk score, risk category, model version, response time, and timestamp.
3. Given the analysis completes through the detection pipeline, when the result is logged, then the stored record preserves the returned result and model version used for that scan.
4. Given the application is restarted, when an Admin later requests scan records, then previously stored prediction records remain available from the prediction-log database.
5. Given the same URL is analysed more than once, when each analysis completes, then each request is stored as a separate scan event because it has its own request ID and timestamp.
6. Given an analysis fails before a complete result is produced, when no successful prediction is returned, then the system does not create a misleading completed-scan record.
7. Given an Admin monitoring API requests scan history, when the backend retrieves records, then it reads them from the prediction-log data store rather than relying only on browser state.

**List**

- Create prediction log entries after each completed analysis.
- Store URL analysis metadata in the prediction log database.
- Make prediction records available for admin dashboard retrieval.

### User Story 9: Record Reported Cases

**US 9 As a system maintainer, I want suspicious website reports to be stored as reviewable cases so that administrators can review repeated reports efficiently.**

**Acceptance Criteria**

1. Given an Employee submits a report for an analysed URL, when the backend receives the report, then it creates a new reviewable case or updates the existing case for that normalized URL.
2. Given the same normalized URL has already been reported, when another report is submitted, then the system appends the report evidence and increases the report count rather than creating an uncontrolled duplicate case.
3. Given a case record is created or updated, when it is stored, then it retains the normalized URL, latest risk category, report count, latest report timestamp, and related model version information.
4. Given several reports belong to the same URL, when an Admin views the case, then the case represents the aggregated reports and can show the associated report metadata.
5. Given a new report is stored for an existing case, when the latest report timestamp changes, then the case becomes eligible to appear earlier in the Admin case ordering.
6. Given feedback persistence fails, when the backend cannot update the case store, then it returns an error and does not claim that the report was accepted.
7. Given an Admin requests reported cases, when the backend retrieves them, then it reads the persistent feedback data rather than a temporary frontend list.

**List**

- Store suspicious website reports in the feedback database.
- Aggregate repeated reports for the same URL into a single reviewable case.
- Track report count and latest report time for each case

## Feature `Admin Monitoring Dashboard`

### User Story 10: View All Recent Scans

**US 10 As an admin, I want to view all recent scan records so that I can monitor system usage and recent phishing detection activity.**

**Acceptance Criteria**

1. Given an authenticated Admin opens the monitoring dashboard, when the scan-records view is requested, then the backend returns stored scan records from the prediction log.
2. Given scan records are available, when the Admin view renders them, then each record displays the analysed URL, risk category, safety score, model version, response time, and creation time.
3. Given scan records have different timestamps, when they are displayed, then the newest records appear before older records.
4. Given an Admin inspects a scan record, when the record is displayed, then it retains the result returned by the detection model for that scan.
5. Given no scans have been recorded, when the Admin opens the scan-records view, then the interface displays an empty-state message rather than failing to render.
6. Given an Employee or unauthenticated user calls the scan-records endpoint, when the backend checks the role, then it rejects the request and does not return scan history.

**List**

- Display all recent scan records in the admin dashboard.
- Retrieve scan records from the prediction log database.
- Sort the records by most recent first.
- Restrict this view to admin users only.

### User Story 11: View Reported Suspicious Cases

**US 11 As an admin, I want to view reported suspicious cases so that I can identify websites that employees have flagged for investigation.**

**Acceptance Criteria**

1. Given an authenticated Admin opens the reported-cases view, when the case data is loaded, then the system displays the stored reviewable cases.
2. Given a case is displayed, when the Admin reads the row, then it includes the URL, risk category, report count, and current case status.
3. Given multiple Employee reports were submitted for the same normalized URL, when the case list is displayed, then the reports are represented as one aggregated case with the combined report count.
4. Given cases have different latest-report times, when the list is displayed, then the most recently reported cases are ordered before older cases.
5. Given a case contains multiple related model versions, when the Admin views its metadata, then the interface can identify that more than one model version is associated with the case.
6. Given no cases have been reported, when the Admin opens the view, then the interface displays a clear empty state.
7. Given an Employee or unauthenticated visitor calls the cases endpoint, when the backend checks the session role, then it rejects the request and does not expose reported-case data.

**List**

- Display reported suspicious cases in the admin dashboard.
- Aggregate repeated reports for the same URL into one case item.
- Sort suspicious cases by latest report time.
- Restrict this view to admin users only.

## Feature `Admin Dashboard Visual Monitoring`

### User Story 12: View Risk Distribution and Model Summary

**US 12 As an admin, I want to view summary charts and model information so that I can quickly understand detection trends and the current system state.**

**Acceptance Criteria**

1. Given an authenticated Admin opens the dashboard overview, when monitoring data is loaded, then the dashboard displays total scans, open cases, reported cases, and average response time.
2. Given one or more scan records exist, when the risk-distribution chart is displayed, then it shows the recorded counts or proportions for `Safe`, `Suspicious`, and `High Risk`.
3. Given no scans exist for a risk category, when the chart is rendered, then the category is still represented with a zero value rather than being omitted.
4. Given model evaluation records are stored, when the model-summary panel is displayed, then it lists recorded model information and comparison values based on the stored evaluation data.
5. Given model metrics are available, when the Admin reads the model summary, then the shown figures originate from recorded evaluation results rather than browser-calculated placeholders.
6. Given the underlying scan, feedback, or model data changes and the Admin dashboard is reloaded, when the overview API is called again, then the displayed values reflect the latest persisted data.
7. Given a non-admin user attempts to access dashboard overview or model-summary data, when the backend validates the request, then it rejects the request with an authorization error.

**List**

- Display admin summary cards for system activity statistics.
- Display a risk distribution chart in the admin dashboard.
- Display model comparison data from evaluation records.
- Retrieve monitoring data from backend admin APIs.
