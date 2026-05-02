package browser

// ObservationType categorizes what the browser observed.
type ObservationType string

const (
	ObsMissingCSRF      ObservationType = "missing_csrf_token"
	ObsInsecureCookie   ObservationType = "insecure_cookie"
	ObsMixedContent     ObservationType = "mixed_content"
	ObsOpenRedirect     ObservationType = "open_redirect"
	ObsSensitiveField   ObservationType = "sensitive_field_exposed"
	ObsAutoComplete     ObservationType = "autocomplete_enabled"
	ObsFormToHTTP       ObservationType = "form_posts_to_http"
	ObsInlineScript     ObservationType = "excessive_inline_scripts"
	ObsMissingHeaders   ObservationType = "missing_security_headers"
	ObsPasswordPlain    ObservationType = "password_field_no_autocomplete_off"
)

// Observation records a single browser-derived security observation.
// Observations are raw; findings are derived from observations with confidence.
type Observation struct {
	Type       ObservationType `json:"type"`
	URL        string          `json:"url"`
	Detail     string          `json:"detail"`
	Element    string          `json:"element,omitempty"`    // CSS selector or element description
	Confidence string          `json:"confidence"`           // high, medium, low
	Severity   string          `json:"severity"`             // critical, high, medium, low, info
	CWEID      int             `json:"cwe_id"`
	RuleID     string          `json:"rule_id"`
}

// ObservationRule defines how to detect a specific observation and what finding to generate.
type ObservationRule struct {
	ID          string          `json:"id"`
	Type        ObservationType `json:"type"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	CWEID       int             `json:"cwe_id"`
	Severity    string          `json:"severity"`
	Confidence  string          `json:"confidence"`
	Category    string          `json:"category"` // maps to dast.Finding.Category
}

// BrowserObservationRules defines the finding generation rules.
// Each rule maps a browser observation to a security finding with CWE, severity, and confidence.
var BrowserObservationRules = []ObservationRule{
	{
		ID:          "BROWSER-001",
		Type:        ObsMissingCSRF,
		Title:       "Form missing CSRF protection",
		Description: "A form that modifies state (POST/PUT/DELETE) lacks a CSRF token field",
		CWEID:       352, // CWE-352: Cross-Site Request Forgery
		Severity:    "medium",
		Confidence:  "high",
		Category:    "csrf",
	},
	{
		ID:          "BROWSER-002",
		Type:        ObsInsecureCookie,
		Title:       "Cookie missing Secure or HttpOnly flag",
		Description: "A session or authentication cookie lacks security attributes",
		CWEID:       614, // CWE-614: Sensitive Cookie Without Secure Flag
		Severity:    "medium",
		Confidence:  "high",
		Category:    "cookie_security",
	},
	{
		ID:          "BROWSER-003",
		Type:        ObsMixedContent,
		Title:       "Mixed content: HTTPS page loads HTTP resources",
		Description: "Active or passive mixed content detected on an HTTPS page",
		CWEID:       319, // CWE-319: Cleartext Transmission
		Severity:    "medium",
		Confidence:  "high",
		Category:    "mixed_content",
	},
	{
		ID:          "BROWSER-004",
		Type:        ObsFormToHTTP,
		Title:       "Form submits to HTTP endpoint",
		Description: "A form on an HTTPS page posts data to an unencrypted HTTP endpoint",
		CWEID:       319,
		Severity:    "high",
		Confidence:  "high",
		Category:    "mixed_content",
	},
	{
		ID:          "BROWSER-005",
		Type:        ObsMissingHeaders,
		Title:       "Missing security response headers",
		Description: "Response lacks recommended security headers (CSP, X-Frame-Options, etc.)",
		CWEID:       693, // CWE-693: Protection Mechanism Failure
		Severity:    "low",
		Confidence:  "high",
		Category:    "headers",
	},
	{
		ID:          "BROWSER-006",
		Type:        ObsAutoComplete,
		Title:       "Sensitive form allows autocomplete",
		Description: "A form with password or credit card fields does not disable autocomplete",
		CWEID:       525, // CWE-525: Information Exposure Through Browser Caching
		Severity:    "low",
		Confidence:  "medium",
		Category:    "information_exposure",
	},
	{
		ID:          "BROWSER-007",
		Type:        ObsInlineScript,
		Title:       "Excessive inline scripts detected",
		Description: "Page contains many inline script tags, increasing XSS attack surface",
		CWEID:       79, // CWE-79: XSS
		Severity:    "info",
		Confidence:  "low",
		Category:    "xss",
	},
}

// RuleByType returns the observation rule matching the given type, or nil.
func RuleByType(t ObservationType) *ObservationRule {
	for i := range BrowserObservationRules {
		if BrowserObservationRules[i].Type == t {
			return &BrowserObservationRules[i]
		}
	}
	return nil
}
