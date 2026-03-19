package correlation

// CWEHierarchy provides parent/child and category lookups for CWE IDs.
type CWEHierarchy struct {
	parents    map[int]int    // cwe_id → parent_id
	categories map[int]string // cwe_id → category name
}

// NewCWEHierarchy builds a hierarchy from a parent map and category map.
func NewCWEHierarchy(parents map[int]int, categories map[int]string) *CWEHierarchy {
	return &CWEHierarchy{parents: parents, categories: categories}
}

// DefaultCWEHierarchy returns a hierarchy with common security-relevant CWEs.
func DefaultCWEHierarchy() *CWEHierarchy {
	parents := map[int]int{
		// Injection family
		89:  943, // SQL Injection → Improper Neutralization of DBMS
		79:  74,  // XSS → Injection
		78:  77,  // OS Command Injection → Command Injection
		77:  74,  // Command Injection → Injection
		943: 74,  // DBMS → Injection
		91:  74,  // XML Injection → Injection
		917: 74,  // Expression Language Injection → Injection
		611: 91,  // XXE → XML Injection

		// Path/File
		22: 706, // Path Traversal → Use of Incorrectly-Resolved Name
		73: 706, // External Control of File Name → Name Resolution

		// SSRF / Request Forgery
		918: 441, // SSRF → Unintended Proxy
		352: 345, // CSRF → Insufficient Verification of Data Authenticity

		// Auth
		287: 284, // Improper Authentication → Improper Access Control
		862: 285, // Missing Authorization → Improper Authorization
		863: 285, // Incorrect Authorization → Improper Authorization
		798: 287, // Hard-coded Credentials → Authentication

		// Data
		502: 913, // Deserialization → Improper Control of Dynamically-Managed Code
		327: 310, // Broken Crypto → Cryptographic Issues
		328: 310, // Reversible One-Way Hash → Cryptographic Issues

		// Information
		200: 668, // Info Exposure → Exposure of Resource
		209: 200, // Error Message Info Leak → Info Exposure
		532: 200, // Log Info Leak → Info Exposure
	}

	categories := map[int]string{
		74:  "injection",
		77:  "injection",
		78:  "injection",
		79:  "injection",
		89:  "injection",
		91:  "injection",
		611: "injection",
		917: "injection",
		943: "injection",

		22:  "file_handling",
		73:  "file_handling",
		706: "file_handling",

		918: "ssrf",
		441: "ssrf",

		352: "auth",
		345: "auth",
		287: "auth",
		284: "auth",
		285: "auth",
		798: "auth",
		862: "auth",
		863: "auth",

		502: "data_integrity",
		913: "data_integrity",

		310: "crypto",
		327: "crypto",
		328: "crypto",

		200: "information",
		209: "information",
		532: "information",
		668: "information",
	}

	return NewCWEHierarchy(parents, categories)
}

// Parent returns the parent CWE ID, or 0 if none.
func (h *CWEHierarchy) Parent(cweID int) int {
	return h.parents[cweID]
}

// Category returns the category name for a CWE, or empty string.
func (h *CWEHierarchy) Category(cweID int) string {
	if cat, ok := h.categories[cweID]; ok {
		return cat
	}
	// Walk up to parent
	if parent, ok := h.parents[cweID]; ok {
		return h.categories[parent]
	}
	return ""
}

// IsRelated returns true if two CWE IDs share a parent or category.
func (h *CWEHierarchy) IsRelated(a, b int) bool {
	if a == b {
		return true
	}
	if h.Parent(a) == b || h.Parent(b) == a {
		return true
	}
	if h.Parent(a) != 0 && h.Parent(a) == h.Parent(b) {
		return true
	}
	catA := h.Category(a)
	catB := h.Category(b)
	return catA != "" && catA == catB
}
