"""Plain-language descriptions for the Module 3 feature schema."""

from __future__ import annotations

from dataclasses import dataclass

from .models import ExplanationDirection, FeatureImpact, TechnicalReason


@dataclass(frozen=True, slots=True)
class FeatureMessage:
    risk_title: str
    risk_detail: str
    safer_title: str
    safer_detail: str


FEATURE_MESSAGES: dict[str, FeatureMessage] = {
    "URLLength": FeatureMessage("Unusual URL length", "The URL length resembles patterns that increased the model's risk estimate.", "URL length appears less suspicious", "The URL length resembles patterns the model associates with lower risk."),
    "DomainLength": FeatureMessage("Unusual domain length", "The domain length contributed to a higher risk estimate.", "Domain length appears more typical", "The domain length contributed to a lower risk estimate."),
    "NoOfSpecialCharsInURL": FeatureMessage("Many structural symbols", "The URL contains a pattern of special characters associated with higher risk.", "URL structure appears simpler", "The URL's use of special characters contributed to a lower risk estimate."),
    "IsDomainIP": FeatureMessage("Raw IP address used", "The website address uses an IP address instead of a recognisable domain name.", "Recognisable domain format", "The address uses a domain-name format rather than a raw IP address."),
    "NoOfSubDomain": FeatureMessage("Complex subdomain structure", "The number of nested subdomains increased the model's risk estimate.", "Simpler subdomain structure", "The subdomain structure contributed to a lower risk estimate."),
    "HasSuspiciousPattern": FeatureMessage("Suspicious wording in the URL", "The URL contains wording or structure commonly seen in deceptive links.", "No strong suspicious wording", "This URL pattern contributed to a lower risk estimate."),
    "SuspiciousPatternCount": FeatureMessage("Several suspicious URL patterns", "Multiple URL patterns associated with phishing contributed to this result.", "Few suspicious URL patterns", "The number of suspicious URL patterns contributed to a lower risk estimate."),
    "BrandSimilarityScore": FeatureMessage("Possible brand impersonation", "The domain is highly similar to a known brand domain and may be attempting to imitate it.", "No strong brand impersonation signal", "The domain did not closely match the monitored brand patterns."),
    "HasBrandImpersonation": FeatureMessage("Possible brand impersonation", "The domain contains a strong similarity signal to a known brand domain.", "No brand impersonation detected", "The domain did not trigger the monitored brand-impersonation rule."),
    "IsKnownOfficialDomain": FeatureMessage("Unrecognised official-domain evidence", "The domain is not in the configured official-domain list.", "Recognised official domain", "The registrable domain matches a configured official domain."),
    "IsKnownOfficialSubdomain": FeatureMessage("Unrecognised subdomain structure", "The subdomain is not in the configured trusted-subdomain list.", "Recognised official subdomain", "The subdomain matches a configured official service pattern."),
    "BrandInDeceptivePosition": FeatureMessage("Brand appears outside the official domain", "A monitored brand name appears in a non-official domain position.", "No deceptive brand placement", "No monitored brand was found in a deceptive domain position."),
    "HasAtSymbol": FeatureMessage("Destination hidden after @ symbol", "The URL contains an @ symbol; the effective destination is the host after that symbol.", "No @ destination trick", "The URL does not use an @ symbol to obscure the effective host."),
    "IsShorteningService": FeatureMessage("Shortened URL destination hidden", "This is a known URL-shortening service, so the final destination must be verified through redirects.", "Direct destination visible", "The URL is not recognised as a known shortening-service address."),
    "HasSensitiveKeyword": FeatureMessage("Sensitive wording requires context", "Sensitive wording appears in the URL, but wording alone is not proof of phishing.", "No sensitive wording detected", "The URL does not contain the monitored sensitive terms."),
    "SensitiveKeywordCount": FeatureMessage("Several sensitive URL terms", "Several sensitive terms appear together and require verification of the destination.", "Few sensitive URL terms", "The URL contains few or no monitored sensitive terms."),
    "HasLongSensitivePath": FeatureMessage("Long credential-related path", "A long path contains several account, security, or verification terms.", "No long credential-related path", "The path does not combine multiple credential-related terms."),
    "UsesHTTPS": FeatureMessage("Connection protection requires caution", "The connection protocol contributed to a higher risk estimate; HTTPS alone does not prove a site is legitimate.", "Encrypted connection available", "The connection protocol contributed to a lower risk estimate, but it is not a safety guarantee."),
    "HTMLAvailable": FeatureMessage("Webpage evidence unavailable", "The system could not retrieve complete webpage content. This is an evidence limitation and does not by itself prove phishing.", "Webpage evidence was available", "Available webpage content contributed to a lower risk estimate."),
    "HasTitle": FeatureMessage("Missing or unusual page title", "The page-title signal contributed to a higher risk estimate.", "Page title appears more consistent", "The page-title signal contributed to a lower risk estimate."),
    "TitleLength": FeatureMessage("Unusual page-title length", "The page-title length contributed to a higher risk estimate.", "Page-title length appears more typical", "The page-title length contributed to a lower risk estimate."),
    "HTMLLength": FeatureMessage("Unusual webpage structure", "The amount of webpage content contributed to a higher risk estimate.", "Webpage structure appears more typical", "The amount of webpage content contributed to a lower risk estimate."),
    "NoOfForms": FeatureMessage("Several forms detected", "The number of forms on the page increased the model's risk estimate.", "Form usage appears less suspicious", "The number of forms contributed to a lower risk estimate."),
    "NoOfInputFields": FeatureMessage("Many information fields", "The number of fields requesting information increased the risk estimate.", "Fewer information fields", "The number of input fields contributed to a lower risk estimate."),
    "NoOfPasswordFields": FeatureMessage("Password fields detected", "Password-entry fields contributed to a higher risk estimate.", "Password-field pattern appears less suspicious", "The password-field pattern contributed to a lower risk estimate."),
    "HasLoginForm": FeatureMessage("Login form detected", "A login form is present and contributed to a higher risk estimate.", "Login-form signal appears less suspicious", "The login-form signal contributed to a lower risk estimate."),
    "HasExternalFormSubmit": FeatureMessage("Information may be sent elsewhere", "The page may send submitted information to a different website.", "Form destination appears more consistent", "The form destination contributed to a lower risk estimate."),
    "NoOfIFrames": FeatureMessage("Embedded page content detected", "The amount of embedded page content increased the model's risk estimate.", "Embedded content appears less suspicious", "The embedded-content pattern contributed to a lower risk estimate."),
    "NoOfScripts": FeatureMessage("Heavy script usage", "The page's script usage contributed to a higher risk estimate.", "Script usage appears more typical", "The page's script usage contributed to a lower risk estimate."),
    "NoOfExternalScripts": FeatureMessage("External scripts detected", "Scripts loaded from other websites contributed to a higher risk estimate.", "External-script pattern appears less suspicious", "The external-script pattern contributed to a lower risk estimate."),
    "NoOfExternalLinks": FeatureMessage("Many external links", "Links leading to other websites contributed to a higher risk estimate.", "External-link pattern appears less suspicious", "The external-link pattern contributed to a lower risk estimate."),
    "RedirectCount": FeatureMessage("Multiple redirects detected", "The link's redirect behaviour increased the model's risk estimate.", "Redirect behaviour appears simpler", "The redirect behaviour contributed to a lower risk estimate."),
    "HasMetaRefresh": FeatureMessage("Automatic page forwarding", "The page contains an automatic forwarding instruction associated with higher risk.", "No risky automatic forwarding signal", "The page-forwarding signal contributed to a lower risk estimate."),
    "HasJavaScriptRedirect": FeatureMessage("Script-based redirection", "The page uses script-based redirection, which contributed to higher risk.", "No risky script-redirection signal", "The script-redirection signal contributed to a lower risk estimate."),
    "DomainTitleMatch": FeatureMessage("Domain and page identity mismatch", "The page title does not appear consistent with the website domain.", "Domain and page identity appear consistent", "The page title and domain relationship contributed to a lower risk estimate."),
    "TitleDomainTokenOverlap": FeatureMessage("Weak domain-title consistency", "The page title and domain share limited identity information.", "Stronger domain-title consistency", "The page title and domain relationship contributed to a lower risk estimate."),
}


def translate_feature_impact(
    impact: FeatureImpact,
    evidence: dict[str, object] | None = None,
) -> TechnicalReason | None:
    message = FEATURE_MESSAGES.get(impact.feature)
    if message is None:
        return None
    if impact.direction is ExplanationDirection.INCREASES_RISK:
        title = message.risk_title
        detail = message.risk_detail
    else:
        title = message.safer_title
        detail = message.safer_detail
    if impact.feature in {"BrandSimilarityScore", "HasBrandImpersonation"} and evidence:
        target = evidence.get("impersonatedDomain")
        brand = evidence.get("impersonatedBrand")
        if target:
            detail = (
                f"The domain closely resembles {target}"
                f"{f' ({brand})' if brand else ''}, which can indicate a typosquatting attempt."
            )
    if impact.feature == "BrandInDeceptivePosition" and evidence:
        target = evidence.get("effectiveRegistrableDomain")
        brand = evidence.get("impersonatedBrand")
        if target:
            detail = (
                f"The effective registrable domain is {target}, while"
                f"{f' {brand}' if brand else ' the monitored brand'} appears elsewhere in the hostname."
            )
    return TechnicalReason(
        feature=impact.feature,
        value=impact.value,
        impact=impact.impact,
        direction=impact.direction,
        title=title,
        detail=detail,
    )
