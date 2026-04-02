package browser

import (
	"testing"
	"time"
)

func TestNewCrawlState_Defaults(t *testing.T) {
	job := BrowserScanJob{} // all zero values
	cs := NewCrawlState(job)

	if cs.MaxURLs != 500 {
		t.Errorf("expected MaxURLs=500, got %d", cs.MaxURLs)
	}
	if cs.MaxDepth != 3 {
		t.Errorf("expected MaxDepth=3, got %d", cs.MaxDepth)
	}
	if cs.MaxDuration != 30*time.Minute {
		t.Errorf("expected MaxDuration=30m, got %v", cs.MaxDuration)
	}
}

func TestNewCrawlState_CustomValues(t *testing.T) {
	job := BrowserScanJob{
		MaxURLs:     100,
		MaxDepth:    2,
		MaxDuration: 10 * time.Minute,
	}
	cs := NewCrawlState(job)

	if cs.MaxURLs != 100 {
		t.Errorf("expected MaxURLs=100, got %d", cs.MaxURLs)
	}
	if cs.MaxDepth != 2 {
		t.Errorf("expected MaxDepth=2, got %d", cs.MaxDepth)
	}
}

func TestCrawlState_Enqueue_DeduplicatesURLs(t *testing.T) {
	job := BrowserScanJob{MaxURLs: 100, MaxDepth: 3}
	cs := NewCrawlState(job)

	// First enqueue succeeds
	if !cs.Enqueue("https://example.com/page", 0) {
		t.Error("first enqueue should succeed")
	}
	// Duplicate is rejected
	if cs.Enqueue("https://example.com/page", 0) {
		t.Error("duplicate should be rejected")
	}
	// Fragment variant is also rejected (normalized to same URL)
	if cs.Enqueue("https://example.com/page#section", 0) {
		t.Error("fragment variant should be deduplicated")
	}
	// Different URL succeeds
	if !cs.Enqueue("https://example.com/other", 0) {
		t.Error("different URL should succeed")
	}

	if len(cs.Queue) != 2 {
		t.Errorf("expected 2 queued URLs, got %d", len(cs.Queue))
	}
}

func TestCrawlState_Enqueue_RejectsExcessiveDepth(t *testing.T) {
	job := BrowserScanJob{MaxURLs: 100, MaxDepth: 2}
	cs := NewCrawlState(job)

	if !cs.Enqueue("https://example.com/", 0) {
		t.Error("depth 0 should be allowed")
	}
	if !cs.Enqueue("https://example.com/a", 2) {
		t.Error("depth 2 (== max) should be allowed")
	}
	if cs.Enqueue("https://example.com/b", 3) {
		t.Error("depth 3 (> max 2) should be rejected")
	}
}

func TestCrawlState_Enqueue_RejectsInvalidURLs(t *testing.T) {
	job := BrowserScanJob{MaxURLs: 100, MaxDepth: 3}
	cs := NewCrawlState(job)

	if cs.Enqueue("javascript:alert(1)", 0) {
		t.Error("javascript: URL should be rejected")
	}
	if cs.Enqueue("data:text/html,<h1>hi</h1>", 0) {
		t.Error("data: URL should be rejected")
	}
	if cs.Enqueue("", 0) {
		t.Error("empty URL should be rejected")
	}
}

func TestCrawlState_Dequeue(t *testing.T) {
	job := BrowserScanJob{MaxURLs: 100, MaxDepth: 3}
	cs := NewCrawlState(job)

	cs.Enqueue("https://example.com/a", 0)
	cs.Enqueue("https://example.com/b", 1)

	entry, ok := cs.Dequeue()
	if !ok || entry.URL != "https://example.com/a" || entry.Depth != 0 {
		t.Errorf("first dequeue: got %+v", entry)
	}
	if cs.URLCount != 1 {
		t.Errorf("expected URLCount=1, got %d", cs.URLCount)
	}

	entry, ok = cs.Dequeue()
	if !ok || entry.URL != "https://example.com/b" {
		t.Errorf("second dequeue: got %+v", entry)
	}

	_, ok = cs.Dequeue()
	if ok {
		t.Error("empty queue should return false")
	}
}

func TestCrawlState_CanContinue_URLBudget(t *testing.T) {
	job := BrowserScanJob{MaxURLs: 2, MaxDepth: 3}
	cs := NewCrawlState(job)

	cs.Enqueue("https://example.com/a", 0)
	cs.Enqueue("https://example.com/b", 0)
	cs.Enqueue("https://example.com/c", 0)

	cs.Dequeue() // count=1
	cs.Dequeue() // count=2

	if cs.CanContinue() {
		t.Error("should not continue after URL budget exhausted")
	}
}

func TestCrawlState_CanContinue_EmptyQueue(t *testing.T) {
	job := BrowserScanJob{MaxURLs: 100, MaxDepth: 3}
	cs := NewCrawlState(job)

	if cs.CanContinue() {
		t.Error("should not continue with empty queue")
	}
}
