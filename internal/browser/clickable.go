package browser

import "strings"

// ClickTarget represents a discoverable interactive element on a page.
type ClickTarget struct {
	Selector string `json:"selector"` // CSS selector to locate element
	Tag      string `json:"tag"`      // element tag name
	Text     string `json:"text"`     // visible text content (trimmed, max 200 chars)
	Role     string `json:"role"`     // ARIA role if present
	Href     string `json:"href"`     // href if any (for router-link, etc.)
	Type     string `json:"type"`     // button type, input type
	Classes  string `json:"classes"`  // CSS classes
	Safety   ClickSafety `json:"safety"`
}

// ClickSafety classifies whether an element is safe to interact with.
type ClickSafety int

const (
	// ClickSafe — navigation elements, tabs, accordions, toggles, router links.
	ClickSafe ClickSafety = iota
	// ClickUnsafe — submit buttons, destructive actions, form controls.
	ClickUnsafe
	// ClickUnknown — cannot determine safety; treat as unsafe.
	ClickUnknown
)

func (cs ClickSafety) String() string {
	switch cs {
	case ClickSafe:
		return "safe"
	case ClickUnsafe:
		return "unsafe"
	default:
		return "unknown"
	}
}

// safeRoles are ARIA roles that indicate navigation/disclosure elements.
var safeRoles = map[string]bool{
	"tab":        true,
	"menuitem":   true,
	"menuitemcheckbox": true,
	"menuitemradio":    true,
	"link":       true,
	"treeitem":   true,
	"option":     true,
	"switch":     true,
}

// safeClassPatterns are CSS class substrings that indicate navigation elements.
var safeClassPatterns = []string{
	"nav", "menu", "tab", "toggle", "accordion", "collapse",
	"dropdown", "expand", "disclosure", "breadcrumb", "pagination",
	"router-link", "nuxt-link",
}

// unsafeTypes are input/button types that are never safe to click.
var unsafeTypes = map[string]bool{
	"submit": true,
	"reset":  true,
	"file":   true,
}

// ClassifyClick determines whether a ClickTarget is safe to interact with.
//
// Safe: navigation elements (tabs, menus, accordions, router-links, pagination).
// Unsafe: submit buttons, destructive keywords, form submission triggers.
// Unknown: cannot determine — treated as unsafe.
func ClassifyClick(ct ClickTarget) ClickSafety {
	text := strings.ToLower(ct.Text)
	tag := strings.ToLower(ct.Tag)
	role := strings.ToLower(ct.Role)
	typ := strings.ToLower(ct.Type)
	classes := strings.ToLower(ct.Classes)

	// Rule 1: Destructive keyword in text → always unsafe
	if IsDestructiveAction(text) {
		return ClickUnsafe
	}

	// Rule 2: Submit/reset/file inputs → unsafe
	if unsafeTypes[typ] {
		return ClickUnsafe
	}

	// Rule 3: button[type=submit] or input[type=submit] → unsafe
	if (tag == "button" || tag == "input") && typ == "submit" {
		return ClickUnsafe
	}

	// Rule 4: Safe ARIA role → safe
	if safeRoles[role] {
		return ClickSafe
	}

	// Rule 5: Anchor tags with href → safe (navigation)
	if tag == "a" && ct.Href != "" {
		return ClickSafe
	}

	// Rule 6: Safe class patterns → safe
	for _, pattern := range safeClassPatterns {
		if strings.Contains(classes, pattern) {
			return ClickSafe
		}
	}

	// Rule 7: data-toggle, data-bs-toggle (Bootstrap), data-action (Stimulus) → safe
	// These are captured in classes field for simplicity
	if strings.Contains(classes, "data-toggle") || strings.Contains(classes, "data-bs-toggle") {
		return ClickSafe
	}

	// Rule 8: Elements inside <nav> are generally safe
	// (This would require parent context which we don't have — skip)

	// Rule 9: Button without type in a form → could submit the form → unsafe
	if tag == "button" && typ == "" {
		return ClickUnsafe // HTML default for button in form is type=submit
	}

	// Rule 10: Standalone button with explicit type=button → safe (non-submitting)
	if tag == "button" && typ == "button" {
		return ClickSafe
	}

	return ClickUnknown
}

// jsExtractClickables extracts interactive elements from the page.
const jsExtractClickables = `(function() {
	var results = [];
	var seen = new Set();
	var selectors = [
		'button',
		'a[href]',
		'[role="tab"]',
		'[role="menuitem"]',
		'[role="link"]',
		'[role="treeitem"]',
		'[role="switch"]',
		'[data-toggle]',
		'[data-bs-toggle]',
		'[data-action]',
		'[onclick]',
		'.nav-link',
		'.tab-link',
		'.accordion-header',
		'.dropdown-toggle',
		'[aria-expanded]',
		'[aria-haspopup]'
	];
	selectors.forEach(function(sel) {
		document.querySelectorAll(sel).forEach(function(el) {
			var key = el.tagName + '|' + (el.textContent || '').trim().substring(0, 50);
			if (seen.has(key)) return;
			seen.add(key);
			var text = (el.textContent || '').trim();
			if (text.length > 200) text = text.substring(0, 200);
			results.push({
				tag: el.tagName.toLowerCase(),
				text: text,
				role: el.getAttribute('role') || '',
				href: el.getAttribute('href') || '',
				type: el.getAttribute('type') || '',
				classes: el.className || '',
				selector: buildSelector(el)
			});
		});
	});
	function buildSelector(el) {
		if (el.id) return '#' + el.id;
		var path = [];
		while (el && el.nodeType === 1) {
			var sel = el.tagName.toLowerCase();
			if (el.id) { path.unshift('#' + el.id); break; }
			var sib = el.parentNode ? el.parentNode.children : [];
			if (sib.length > 1) {
				var idx = Array.from(sib).indexOf(el) + 1;
				sel += ':nth-child(' + idx + ')';
			}
			path.unshift(sel);
			el = el.parentNode;
		}
		return path.join(' > ');
	}
	return results;
})()`
