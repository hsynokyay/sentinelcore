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

// sensitiveHeaders are redacted from evidence capture.
var sensitiveHeaders = map[string]bool{
	"authorization":   true,
	"cookie":          true,
	"set-cookie":      true,
	"x-api-key":       true,
	"x-auth-token":    true,
	"proxy-authorization": true,
}

// sensitivePatterns match credential-like values in bodies.
var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)"?(password|passwd|secret|token|api[_-]?key|auth)"?\s*[:=]\s*"?[^\s"',}]+`),
	regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9._\-]+`),
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
		if sensitiveHeaders[strings.ToLower(k)] {
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
		if sensitiveHeaders[strings.ToLower(k)] {
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
	for _, pattern := range sensitivePatterns {
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
