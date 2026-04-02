package dast

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
	"time"
)

// Evidence captures a complete HTTP request/response pair for a finding.
type Evidence struct {
	ID           string            `json:"id"`
	ScanJobID    string            `json:"scan_job_id"`
	RuleID       string            `json:"rule_id"`
	Request      HTTPRequest       `json:"request"`
	Response     HTTPResponse      `json:"response"`
	TimingMs     int64             `json:"timing_ms"`
	SHA256       string            `json:"sha256"`
	CapturedAt   time.Time         `json:"captured_at"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// HTTPRequest captures request details with credentials redacted.
type HTTPRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

// HTTPResponse captures response details.
type HTTPResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body,omitempty"`
	BodySize   int64             `json:"body_size"`
}

const maxEvidenceBodySize = 1 << 20 // 1 MB

// SensitiveHeaders are redacted from evidence capture. Exported for reuse by browser worker.
var SensitiveHeaders = map[string]bool{
	"authorization":          true,
	"cookie":                 true,
	"set-cookie":             true,
	"x-api-key":              true,
	"x-auth-token":           true,
	"x-csrf-token":           true,
	"x-xsrf-token":           true,
	"proxy-authorization":    true,
	"proxy-authentication-info": true,
}

// SensitivePatterns match credential-like values in bodies. Exported for reuse by browser worker.
var SensitivePatterns = []*regexp.Regexp{
	// Key-value credentials: password=xxx, "secret": "xxx", token: xxx
	regexp.MustCompile(`(?i)"?(password|passwd|secret|token|api[_-]?key|auth|credential|client_secret)"?\s*[:=]\s*"?[^\s"',}]+`),
	// Bearer tokens
	regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9._\-]+`),
	// Basic auth
	regexp.MustCompile(`(?i)basic\s+[A-Za-z0-9+/=]+`),
	// JWT tokens (three base64url segments)
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+`),
	// AWS access key IDs
	regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
	// Private keys
	regexp.MustCompile(`-----BEGIN\s+(RSA\s+|EC\s+)?PRIVATE\s+KEY-----`),
	// GitHub tokens
	regexp.MustCompile(`gh[ps]_[A-Za-z0-9_]{36,}`),
}

// CaptureEvidence creates an Evidence record from an HTTP request and response.
func CaptureEvidence(req *http.Request, resp *http.Response, ruleID, scanJobID string, timing time.Duration) (*Evidence, error) {
	ev := &Evidence{
		ScanJobID:  scanJobID,
		RuleID:     ruleID,
		TimingMs:   timing.Milliseconds(),
		CapturedAt: time.Now(),
	}

	// Capture request
	ev.Request = captureRequest(req)

	// Capture response
	if resp != nil {
		ev.Response = captureResponse(resp)
	}

	// Compute integrity hash
	ev.SHA256 = computeEvidenceHash(ev)

	return ev, nil
}

func captureRequest(req *http.Request) HTTPRequest {
	hr := HTTPRequest{
		Method:  req.Method,
		URL:     req.URL.String(),
		Headers: make(map[string]string),
	}

	for k, vals := range req.Header {
		if SensitiveHeaders[strings.ToLower(k)] {
			hr.Headers[k] = "[REDACTED]"
		} else {
			hr.Headers[k] = strings.Join(vals, ", ")
		}
	}

	if req.Body != nil && req.GetBody != nil {
		body, err := req.GetBody()
		if err == nil {
			raw, _ := httputil.DumpRequest(&http.Request{Body: body}, true)
			bodyStr := redactBody(string(raw))
			if len(bodyStr) > maxEvidenceBodySize {
				bodyStr = bodyStr[:maxEvidenceBodySize] + "\n[TRUNCATED]"
			}
			hr.Body = bodyStr
		}
	}

	return hr
}

func captureResponse(resp *http.Response) HTTPResponse {
	hr := HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    make(map[string]string),
	}

	for k, vals := range resp.Header {
		if SensitiveHeaders[strings.ToLower(k)] {
			hr.Headers[k] = "[REDACTED]"
		} else {
			hr.Headers[k] = strings.Join(vals, ", ")
		}
	}

	if resp.Body != nil {
		raw, err := httputil.DumpResponse(resp, true)
		if err == nil {
			// Extract body from dump (skip headers)
			parts := strings.SplitN(string(raw), "\r\n\r\n", 2)
			if len(parts) == 2 {
				body := redactBody(parts[1])
				hr.BodySize = int64(len(body))
				if len(body) > maxEvidenceBodySize {
					body = body[:maxEvidenceBodySize] + "\n[TRUNCATED]"
				}
				hr.Body = body
			}
		}
	}

	return hr
}

func redactBody(body string) string {
	result := body
	for _, pattern := range SensitivePatterns {
		result = pattern.ReplaceAllString(result, "[REDACTED]")
	}
	return result
}

func computeEvidenceHash(ev *Evidence) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%d|%s|%d",
		ev.Request.Method,
		ev.Request.URL,
		ev.Request.Body,
		ev.Response.StatusCode,
		ev.Response.Body,
		ev.TimingMs,
	)
	return hex.EncodeToString(h.Sum(nil))
}

// captureEvidenceFromBytes creates evidence from pre-read request/response bytes.
// This prevents double-consumption of response bodies.
func captureEvidenceFromBytes(req *http.Request, resp *http.Response, respBody []byte, ruleID, scanJobID string, timing time.Duration) *Evidence {
	ev := &Evidence{
		ScanJobID:  scanJobID,
		RuleID:     ruleID,
		TimingMs:   timing.Milliseconds(),
		CapturedAt: time.Now(),
	}

	// Capture request
	ev.Request = captureRequest(req)

	// Capture response from pre-read bytes
	if resp != nil {
		hr := HTTPResponse{
			StatusCode: resp.StatusCode,
			Headers:    make(map[string]string),
			BodySize:   int64(len(respBody)),
		}
		for k, vals := range resp.Header {
			if SensitiveHeaders[strings.ToLower(k)] {
				hr.Headers[k] = "[REDACTED]"
			} else {
				hr.Headers[k] = strings.Join(vals, ", ")
			}
		}
		body := redactBody(string(respBody))
		if len(body) > maxEvidenceBodySize {
			body = body[:maxEvidenceBodySize] + "\n[TRUNCATED]"
		}
		hr.Body = body
		ev.Response = hr
	}

	ev.SHA256 = computeEvidenceHash(ev)
	return ev
}

// RedactURL removes credentials from a URL string.
func RedactURL(rawURL string) string {
	// Remove userinfo from URL
	if idx := strings.Index(rawURL, "@"); idx > 0 {
		schemeEnd := strings.Index(rawURL, "://")
		if schemeEnd > 0 && schemeEnd < idx {
			return rawURL[:schemeEnd+3] + "[REDACTED]@" + rawURL[idx+1:]
		}
	}
	return rawURL
}
