package recording

import (
	"sync"
	"testing"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
)

func TestRecordAction_Concurrency(t *testing.T) {
	r := &Recorder{}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.recordAction(bundles.Action{Kind: bundles.ActionNavigate, URL: "x", Timestamp: time.Now()})
		}()
	}
	wg.Wait()
	if len(r.actions) != 100 {
		t.Errorf("expected 100 actions, got %d", len(r.actions))
	}
}
