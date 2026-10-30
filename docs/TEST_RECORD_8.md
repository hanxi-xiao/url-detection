# ClearURL Testing Record #8

## Document Information

- Project: `ClearURL`
- Repository: `url-detection-main`
- Document Type: `Testing Record`
- Purpose: Third-round verification-status integration and unreachable-domain handling
- Date: `2026-08-12`

## Version Under Test

- Model name: `xgboost`
- Model version: `xgboost-20260806T143316Z`
- Dataset version: `phiusiil-v9-official-domain-guardrails`
- Feature schema: `clearurl-m3-v3`
- Verification-status integration: enabled in backend and frontend

## Automated Verification

| Record ID   | Area                      | Test Method                                                        | Expected Result                                                 | Actual Output                                    | Status |
| ----------- | ------------------------- | ------------------------------------------------------------------ | --------------------------------------------------------------- | ------------------------------------------------ | ------ |
| AUTO-008-01 | Backend regression        | `conda run --no-capture-output -n torch3.10 python -m pytest -q` | All regression tests pass after verification-status integration | `22 passed in 1.90s`                           | Pass   |
| AUTO-008-02 | Frontend production build | `npm run build`                                                  | Frontend builds successfully with the new verification UI block | Production assets built successfully in`114ms` | Pass   |

## Verification-Status Results

| Record ID  | URL                                                  | Expected Result                                                                         | Actual Output                                                                                                                                          | Status                  |
| ---------- | ---------------------------------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------- |
| VER-008-01 | `https://abcdef123456789.com`                      | Unknown destination should not be shown as confirmed phishing                           | Verification`UNABLE_TO_VERIFY`; final risk `Suspicious`; safety score `11/100`                                                                   | Pass                    |
| VER-008-02 | `https://this-domain-does-not-exist-123456789.com` | Non-resolving destination should be separated from confirmed phishing                   | Verification`UNABLE_TO_VERIFY`; final risk `Suspicious`; safety score `11/100`                                                                   | Pass                    |
| VER-008-03 | `https://bit.ly/example`                           | Short-link destination should be shown as unresolved                                    | Verification`SHORT_LINK_UNRESOLVED`; final risk `Suspicious`; safety score `11/100`                                                              | Pass                    |
| VER-008-04 | `https://google.com@evil-login.com`                | Obfuscated destination should still remain dangerous even if webpage verification fails | Verification`UNABLE_TO_VERIFY`; final risk `High Risk`; safety score `0/100`; explanation states the effective destination is `evil-login.com` | Pass                    |
| VER-008-05 | `https://accounts.google.com`                      | Official service should remain recognisable even when webpage fetch fails               | Verification should show recognised-official-domain status rather than generic unreachable-destination status                                          | Pass after priority fix |

## Outcome Summary

This round separates three situations that were previously mixed together:

1. `Official domain recognised`
2. `Short-link destination not verified`
3. `Destination could not be verified`

As a result, unreachable or unresolved URLs no longer need to be displayed as confirmed
`High Risk` when only weak URL evidence is present. At the same time, structurally
dangerous URLs such as `google.com@evil-login.com` still remain `High Risk`.
