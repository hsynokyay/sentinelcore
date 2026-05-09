package recording

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/chromedp/chromedp"
)

// skeletonJS extracts a coarse-grained "skeleton" of the current page from
// the chromedp-controlled browser. It deliberately ignores values, dynamic
// text, and styling so that a replay landing on the same page produces an
// identical hash even if visit-specific tokens (CSRF, timestamps, …) differ.
//
// The shape returned is JSON: {path, form, h, nav}.
//   - path: location.pathname (no host, no query, no fragment)
//   - form: sorted names/ids of visible <input>, <select>, <textarea>, <button>
//   - h:    text of <h1>/<h2> elements, trimmed to ≤80 chars each
//   - nav:  text of <nav>/<header>/<aside> landmarks, trimmed to ≤80 chars
const skeletonJS = `(() => {
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  };
  const ident = (el) => (el.name || el.id || '').trim();
  const trim80 = (s) => (s || '').trim().slice(0, 80);
  const form = [];
  document.querySelectorAll('input, select, textarea, button').forEach((el) => {
    if (!visible(el)) return;
    const id = ident(el);
    if (id) form.push(id);
  });
  const h = [];
  document.querySelectorAll('h1, h2').forEach((el) => {
    const t = trim80(el.textContent);
    if (t) h.push(t);
  });
  const nav = [];
  document.querySelectorAll('nav, header, aside').forEach((el) => {
    const t = trim80(el.textContent);
    if (t) nav.push(t);
  });
  return JSON.stringify({path: location.pathname, form, h, nav});
})()`

// skeleton mirrors the JSON shape produced by skeletonJS.
type skeleton struct {
	Path string   `json:"path"`
	Form []string `json:"form"`
	H    []string `json:"h"`
	Nav  []string `json:"nav"`
}

// ComputePostStateHash evaluates the skeleton extractor in the active
// chromedp context and returns the canonical SHA-256 hex digest of the
// resulting page skeleton. It returns an error only when the chromedp
// evaluation itself fails; bad JSON falls back to hashing raw bytes.
func ComputePostStateHash(ctx context.Context) (string, error) {
	var raw string
	if err := chromedp.Run(ctx, chromedp.Evaluate(skeletonJS, &raw)); err != nil {
		return "", err
	}
	return canonicalize(raw), nil
}

// canonicalize parses raw as a skeleton, sorts the variable-order slices,
// joins the four fields with "|", and returns the SHA-256 hex digest. If
// parsing fails (e.g. a non-JSON payload), the raw bytes are hashed
// directly so callers always see a 64-char hex digest.
func canonicalize(raw string) string {
	var s skeleton
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		sum := sha256.Sum256([]byte(raw))
		return hex.EncodeToString(sum[:])
	}
	sort.Strings(s.Form)
	sort.Strings(s.H)
	sort.Strings(s.Nav)
	canon := s.Path + "|" +
		strings.Join(s.Form, ",") + "|" +
		strings.Join(s.H, ",") + "|" +
		strings.Join(s.Nav, ",")
	sum := sha256.Sum256([]byte(canon))
	return hex.EncodeToString(sum[:])
}
