package browser

import "time"

// CrawlState tracks the progress of a browser crawl session.
type CrawlState struct {
	Visited    map[string]bool // normalized URL → visited
	Queue      []CrawlEntry   // BFS queue
	Pages      []PageResult   // collected results
	StartedAt  time.Time
	URLCount   int
	MaxURLs    int
	MaxDepth   int
	MaxDuration time.Duration
}

// CrawlEntry is a URL queued for visiting at a given depth.
type CrawlEntry struct {
	URL   string
	Depth int
}

// NewCrawlState creates a CrawlState with budget limits from a BrowserScanJob.
func NewCrawlState(job BrowserScanJob) *CrawlState {
	maxURLs := job.MaxURLs
	if maxURLs <= 0 {
		maxURLs = 500
	}
	maxDepth := job.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 3
	}
	maxDuration := job.MaxDuration
	if maxDuration <= 0 {
		maxDuration = 30 * time.Minute
	}
	return &CrawlState{
		Visited:     make(map[string]bool),
		StartedAt:   time.Now(),
		MaxURLs:     maxURLs,
		MaxDepth:    maxDepth,
		MaxDuration: maxDuration,
	}
}

// CanContinue returns true if crawl budget has not been exhausted.
func (cs *CrawlState) CanContinue() bool {
	if cs.URLCount >= cs.MaxURLs {
		return false
	}
	if time.Since(cs.StartedAt) >= cs.MaxDuration {
		return false
	}
	return len(cs.Queue) > 0
}

// Enqueue adds a URL to the crawl queue if it hasn't been visited
// and the depth is within budget.
func (cs *CrawlState) Enqueue(url string, depth int) bool {
	if depth > cs.MaxDepth {
		return false
	}
	normalized := NormalizeURL(url)
	if normalized == "" {
		return false
	}
	if cs.Visited[normalized] {
		return false
	}
	cs.Visited[normalized] = true
	cs.Queue = append(cs.Queue, CrawlEntry{URL: url, Depth: depth})
	return true
}

// Dequeue removes and returns the next URL to visit.
func (cs *CrawlState) Dequeue() (CrawlEntry, bool) {
	if len(cs.Queue) == 0 {
		return CrawlEntry{}, false
	}
	entry := cs.Queue[0]
	cs.Queue = cs.Queue[1:]
	cs.URLCount++
	return entry, true
}

// PageResult captures the outcome of visiting a single page.
type PageResult struct {
	URL       string        `json:"url"`
	Title     string        `json:"title"`
	Depth     int           `json:"depth"`
	Links     []string      `json:"links"`
	Forms     []FormInfo    `json:"forms"`
	LoadTime  time.Duration `json:"load_time"`
	Error     string        `json:"error,omitempty"`
}

// FormInfo describes a discovered HTML form.
type FormInfo struct {
	Action   string      `json:"action"`
	Method   string      `json:"method"`
	Fields   []FormField `json:"fields"`
	HasCSRF  bool        `json:"has_csrf"`
	IsSafe   bool        `json:"is_safe"`
}

// FormField describes a single form input.
type FormField struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
}
