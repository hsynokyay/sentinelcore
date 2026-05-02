package engine

// FunctionSummary captures the taint behavior of a single function for a
// specific vulnerability class so that callers can apply the summary without
// re-analyzing the callee body.
//
// Summaries are keyed by (FQN, VulnClass) because the same function can
// exhibit different taint behavior depending on which sinks are relevant.
// For example, a function that builds a SQL query AND opens a file would
// have two separate summaries: one for sql_injection and one for
// path_traversal.
type FunctionSummary struct {
	FQN       string
	VulnClass string

	ParamCount    int
	ReturnTainted map[int]bool
	SinkReachable map[int][]SinkHit
}

// SinkHit records that taint reached a specific sink.
type SinkHit struct {
	SinkFQN   string
	VulnClass string
	SinkLine  int
}

// SummaryCache maps (function FQN, vuln class) → summary.
type SummaryCache struct {
	cache map[string]*FunctionSummary
}

func NewSummaryCache() *SummaryCache {
	return &SummaryCache{cache: map[string]*FunctionSummary{}}
}

func summaryKey(fqn, vulnClass string) string {
	return fqn + "::" + vulnClass
}

func (sc *SummaryCache) Get(fqn, vulnClass string) *FunctionSummary {
	return sc.cache[summaryKey(fqn, vulnClass)]
}

func (sc *SummaryCache) Put(s *FunctionSummary) {
	sc.cache[summaryKey(s.FQN, s.VulnClass)] = s
}
