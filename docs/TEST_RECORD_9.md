# ClearURL Testing Record #9

## Document Information

- Project: `ClearURL`
- Repository: `url-detection-main`
- Document Type: `Testing Record`
- Purpose: Verification of administrator-reviewed allowlist and blocklist handling
- Date: `2026-08-16`

## Version Under Test

- Detection model: `xgboost`
- Model version: `xgboost-20260806T143316Z`
- Dataset version: `phiusiil-v9-official-domain-guardrails`
- Feature schema: `clearurl-m3-v3`
- Policy override schema: `policy-override-v1`
- Feedback persistence: `data/clearurl-feedback.sqlite3`

## Scope

This test record covers the new human-review workflow introduced after employee
feedback submission:

1. Employees can submit a risk report or request a review of a model result.
2. Administrators can review an open case and decide to add the exact normalised
   URL to an allowlist or blocklist.
3. A reason is mandatory for every administrator list decision.
4. Screenshot evidence is optional and is retained with the administrator decision.
5. A later employee submission checks the reviewed list before webpage retrieval,
   feature extraction, and model inference.
6. The employee response identifies the reviewed policy decision through a distinct
   verification status and explanation.

The policy list applies to the exact normalised URL. It does not automatically
allowlist or blocklist every URL under the same domain.

## Automated Verification

| Record ID   | Area                      | Test Method                                                        | Expected Result                                                                                                            | Actual Output                                | Status |
| ----------- | ------------------------- | ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- | ------ |
| AUTO-009-01 | Full backend regression   | `conda run --no-capture-output -n torch3.10 python -m pytest -q` | Existing behaviour and new policy-list tests pass                                                                          | `29 passed in 1.99s`                       | Pass   |
| AUTO-009-02 | Frontend production build | `npm run build`                                                  | TypeScript compilation and production bundle complete after the administrator modal and scrollable review queue were added | Vite build completed successfully in`81ms` | Pass   |

## Policy Override Regression Results

| Record ID  | Scenario                                | Test Input / Action                                                                                                                                                    | Expected Result                                                                                             | Actual Output                                                                                                       | Status |
| ---------- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ------ |
| POL-009-01 | Create an allowlist decision            | Analyse`https://trusted-admin-review.example.com/login`; submit employee review feedback; resolve the resulting case as `allowlist` with an administrator reason   | A persistent allowlist entry and resolved case are created                                                  | The regression test completed the decision successfully                                                             | Pass   |
| POL-009-02 | Allowlist lookup before model inference | Re-submit`https://trusted-admin-review.example.com/login` after the allowlist decision                                                                               | Result is`Safe`; the response identifies an administrator allowlist match instead of model inference      | `riskCategory=Safe`; `verification.code=ADMIN_ALLOWLIST_MATCH`; `prediction.model_name=policy-allowlist`      | Pass   |
| POL-009-03 | Create a blocklist decision             | Analyse`https://confirmed-phishing-admin.example.com/login`; submit employee risk feedback; resolve the resulting case as `blocklist` with an administrator reason | A persistent blocklist entry and resolved case are created                                                  | The regression test completed the decision successfully                                                             | Pass   |
| POL-009-04 | Blocklist lookup before model inference | Re-submit`https://confirmed-phishing-admin.example.com/login` after the blocklist decision                                                                           | Result is`High Risk`; the response identifies an administrator blocklist match instead of model inference | `riskCategory=High Risk`; `verification.code=ADMIN_BLOCKLIST_MATCH`; `prediction.model_name=policy-blocklist` | Pass   |
| POL-009-05 | Case status and evidence metadata       | Resolve a review case as`allowlist` with reason `Admin validated this URL as safe.`, screenshot name `portal.png`, and image data                                | Case status and decision metadata are retained for the management view                                      | `status=ALLOWLISTED`; `adminDecision=allowlist`; reason and screenshot name persisted                           | Pass   |

## Administrator Review Controls

| Record ID  | Control                      | Expected Behaviour                                                                                                                               | Verification Method                                                                                             | Status |
| ---------- | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------- | ------ |
| ADM-009-01 | Mandatory decision reason    | The administrator cannot continue to the final confirmation without entering a review reason                                                     | Frontend validation and backend validation implemented; backend regression covers successful reason persistence | Pass   |
| ADM-009-02 | Optional screenshot evidence | The administrator can select a PNG, JPEG, or WebP screenshot; attached evidence is displayed as a preview before submission                      | Frontend build verification completed                                                                           | Pass   |
| ADM-009-03 | Confirmation step            | The administrator must select`Continue`, then explicitly select `Confirm and apply` before the policy entry is stored                        | Frontend build verification completed                                                                           | Pass   |
| ADM-009-04 | Review queue status          | The case list shows`Pending review`, `Allowlisted`, or `Blocklisted`, together with the employee report summary and administrator decision | Frontend build verification completed; backend case-status persistence verified                                 | Pass   |
| ADM-009-05 | Report history capacity      | The case queue and report-history area are constrained with vertical scrolling so additional reports do not expand the dashboard indefinitely    | Frontend build verification completed                                                                           | Pass   |

## Employee-Facing Policy Results

| Policy Type | Risk Result   | Safety Score | Verification Code         | Explanation Intent                                                                                       |
| ----------- | ------------- | -----------: | ------------------------- | -------------------------------------------------------------------------------------------------------- |
| Allowlist   | `Safe`      |      `100` | `ADMIN_ALLOWLIST_MATCH` | Explains that an administrator-reviewed allowlist decision overrides model inference for this exact URL. |
| Blocklist   | `High Risk` |        `0` | `ADMIN_BLOCKLIST_MATCH` | Explains that an administrator-reviewed blocklist decision overrides model inference for this exact URL. |

## Outcome Summary

The completed regression tests confirm that a case can move from employee feedback
to an administrator-reviewed list decision, and that the stored decision changes
future analysis results before the normal model pipeline is called.

This design avoids automatically trusting or blocking an entire domain from a single
report. Each decision is recorded against the exact normalised URL, with the case,
administrator identity, timestamp, mandatory rationale, and optional screenshot
evidence retained in the feedback database.

## Remaining Manual Validation

The following acceptance checks should be completed in a browser before the next
demonstration or deployment update:

1. Log in as an administrator, open a pending case, attach a real screenshot, and
   confirm that the preview and final confirmation interaction are clear.
2. Submit the same URL as an employee after an allowlist or blocklist decision and
   confirm that the verification card displays the corresponding administrator-list
   status.
3. Confirm that long URLs and a large number of reports remain usable in the
   scrollable case queue on desktop and mobile layouts.
