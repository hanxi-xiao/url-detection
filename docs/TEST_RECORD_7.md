# ClearURL Testing Record #7

## Document Information

- Project: `ClearURL`
- Repository: `url-detection-main`
- Document Type: `Testing Record`
- Purpose: Second-round regression after official-domain guardrails and raw-URL obfuscation fixes
- Date: `2026-08-08`

## Version Under Test

- Model name: `xgboost`
- Model version: `xgboost-20260806T143316Z`
- Dataset version: `phiusiil-v9-official-domain-guardrails`
- Feature schema: `clearurl-m3-v3`
- Feature count: `24`
- Explanation mode: `tree-shap-local-contributions`

## Automated Verification

| Record ID   | Area                      | Test Method                                                        | Expected Result                                                                             | Actual Output                                                                                                                                   | Status |
| ----------- | ------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| AUTO-007-01 | Backend regression        | `conda run --no-capture-output -n torch3.10 python -m pytest -q` | All backend regression tests pass after the second-round changes                            | `..................... [100%]`; `21 passed in 3.79s`                                                                                        | Pass   |
| AUTO-007-02 | Model retraining          | `python -m app.module4.train ...`                                | A new model artifact is generated with the updated dataset version and feature set          | Active artifact updated to`xgboost-20260806T143316Z`; dataset version `phiusiil-v9-official-domain-guardrails`                              | Pass   |
| AUTO-007-03 | Raw URL signal extraction | direct feature-extraction verification                             | The extractor preserves`@` obfuscation and official-domain signals from the submitted URL | `HasAtSymbol=1` for `google.com@evil-login.com`; `IsKnownOfficialDomain=1` and `IsKnownOfficialSubdomain=1` for `accounts.google.com` | Pass   |

## Second-Round Acceptance Regression

| Record ID  | URL                                                | Expected Result                                                              | Actual Output                                                                                                                                                               | Status |
| ---------- | -------------------------------------------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| REG-007-01 | `https://www.google.com`                         | Low risk as an official domain                                               | `Safe`; risk score `35/100`; safety score `65/100`; explanation includes `Recognised official domain`                                                               | Pass   |
| REG-007-02 | `https://www.amazon.com`                         | Low risk as an official domain                                               | `Safe`; risk score `35/100`; safety score `65/100`; explanation includes `Recognised official domain`                                                               | Pass   |
| REG-007-03 | `https://github.com/login`                       | Should not be treated as phishing solely because of`login`                 | `Safe`; risk score `35/100`; safety score `65/100`; explanation includes `Recognised official domain` and missing-web-evidence limitation                           | Pass   |
| REG-007-04 | `https://accounts.google.com`                    | Low risk as an official login subdomain                                      | `Safe`; risk score `35/100`; safety score `65/100`; explanation includes `Recognised official domain`                                                               | Pass   |
| REG-007-05 | `https://login.microsoftonline.com`              | Low risk as an official Microsoft login subdomain                            | `Safe`; risk score `35/100`; safety score `65/100`; explanation includes `Recognised official domain`                                                               | Pass   |
| REG-007-06 | `https://go0gle.com`                             | High risk for Google character substitution                                  | `High Risk`; risk score `99.89/100`; explanation names `google.com (Google)`                                                                                          | Pass   |
| REG-007-07 | `https://g00gle.com`                             | High risk for Google character substitution                                  | `High Risk`; risk score `99.89/100`; explanation names `google.com (Google)`                                                                                          | Pass   |
| REG-007-08 | `https://google-security.com`                    | High risk or strong suspicious signal for non-official Google-branded domain | `High Risk`; risk score `99.91/100`; explanation states that the effective registrable domain is `google-security.com` while Google appears elsewhere in the hostname | Pass   |
| REG-007-09 | `https://google-login.com`                       | High risk for brand + login combination                                      | `High Risk`; risk score `99.73/100`; explanation states that the effective registrable domain is `google-login.com` while Google appears elsewhere in the hostname    | Pass   |
| REG-007-10 | `https://paypal.com.verify-account-security.com` | High risk because PayPal appears in a deceptive subdomain position           | `High Risk`; risk score `99.32/100`; explanation states that the effective registrable domain is `verify-account-security.com`, not PayPal                            | Pass   |
| REG-007-11 | `https://google.com@evil-login.com`              | High risk and explicit`@` obfuscation explanation                          | `High Risk`; risk score `99.83/100`; explanation: `The effective destination is evil-login.com, not the text before @.`                                               | Pass   |
| REG-007-12 | `https://bit.ly/example`                         | Medium or suspicious rather than directly safe                               | `Suspicious`; risk score `89/100`; safety score `11/100`; explanation states that the shortened destination must be inspected through redirects                       | Pass   |

## Cases Still Not Fully Solved

| Record ID  | URL                                                                                     | Current Output                                                                                             | Assessment                                                                                                                               |
| ---------- | --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| GAP-007-01 | `https://abcdef123456789.com`                                                         | `Suspicious`; risk score `89/100`; explanation mainly says webpage evidence was unavailable            | Improved from the first round because it is no longer marked`Safe`, but the system still lacks a dedicated `Unable to Verify` state. |
| GAP-007-02 | `https://this-domain-does-not-exist-123456789.com`                                    | `High Risk`; risk score `98.18/100`; explanation focuses on structural symbols and suspicious patterns | Still too aggressive for a non-resolving domain. DNS failure and confirmed phishing are not yet separated cleanly.                       |
| GAP-007-03 | `https://example.com/user/login/account/security/verify/password/reset/session/check` | `High Risk`; risk score `99.82/100`; explanation cites URL length and missing webpage evidence         | The model still leans too heavily on long sensitive paths when the destination is otherwise unknown.                                     |

## Key Improvement Summary

Compared with the previous round:

1. Official login domains are no longer penalised into `High Risk` simply because the path or subdomain contains `login`, `account`, or similar wording.
2. Raw URL obfuscation is now preserved during feature extraction, so `google.com@evil-login.com` produces a specific `@`-based explanation instead of a generic warning.
3. Deceptive brand placement is now distinguishable from exact brand-domain typosquatting.
4. Shortening services are now identified explicitly and explained as hidden-destination links rather than being treated as ordinary low-context URLs.

## Verification Status Integration

The frontend and backend now expose a dedicated verification-status field alongside
the risk classification. This separates phishing risk from verification completeness.

Observed outputs:

| URL                                   | Verification Code            | Verification Label                      | Meaning                                                                        |
| ------------------------------------- | ---------------------------- | --------------------------------------- | ------------------------------------------------------------------------------ |
| `https://accounts.google.com`       | `OFFICIAL_DOMAIN_ONLY`     | `Official domain recognised`          | The domain is trusted, but webpage HTML was not available during analysis.     |
| `https://www.google.com`            | `OFFICIAL_DOMAIN_ONLY`     | `Official domain recognised`          | The result relied on recognised official-domain identity without webpage HTML. |
| `https://bit.ly/example`            | `SHORT_LINK_UNRESOLVED`    | `Short-link destination not verified` | The URL is a shortening service and the final destination was not confirmed.   |
| `https://google.com@evil-login.com` | `LIMITED_WEB_VERIFICATION` | `Webpage verification limited`        | URL-structure evidence was analysed, but webpage retrieval did not complete.   |

This verification block is now displayed separately in the employee result page so
users can see whether the conclusion came from confirmed webpage content, official
domain identity, or limited URL-only evidence.

## Follow-Up Recommendation

The next engineering step should refine the verification states further by introducing
a dedicated `Unable to Verify` state for DNS failure and unreachable domains, so that
network failure, blocked HTML retrieval, and confirmed phishing are not compressed
into the same final risk scale.
