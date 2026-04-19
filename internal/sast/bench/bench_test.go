package bench

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestBenchmark is the entry point for running the SentinelCore SAST
// benchmark. It loads the corpus, runs the engine, and prints the scorecard.
//
// Run with:
//   go test -v ./internal/sast/bench/ -run TestBenchmark
func TestBenchmark(t *testing.T) {
	corpusDir := filepath.Join("corpus")
	manifestPath := filepath.Join("manifest.json")

	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Skip("manifest.json not found — run from the bench/ directory")
	}

	result, err := Run(corpusDir, manifestPath)
	if err != nil {
		t.Fatalf("benchmark run failed: %v", err)
	}

	PrintScorecard(result)

	// Write markdown scorecard to file
	md := ScorecardMarkdown(result)
	if err := os.WriteFile("scorecard.md", []byte(md), 0o644); err != nil {
		t.Logf("warning: could not write scorecard.md: %v", err)
	}

	// Assert minimum quality bar
	if result.Overall.F1 < 0.5 {
		t.Errorf("overall F1 = %.2f, want >= 0.50", result.Overall.F1)
	}

	// Log individual case outcomes for debugging
	for _, c := range result.Cases {
		status := "OK"
		if c.Outcome == "FN" || c.Outcome == "FP" {
			status = "FAIL"
		}
		t.Logf("  [%s] %s %s → %s (findings: %d)",
			status, c.Outcome, c.Case.ID, c.Case.File, len(c.Findings))
	}

	// Report summary
	fmt.Printf("\n=== Benchmark Summary ===\n")
	fmt.Printf("Total cases: %d\n", result.Overall.Total)
	fmt.Printf("True positives: %d\n", result.Overall.TP)
	fmt.Printf("False positives: %d\n", result.Overall.FP)
	fmt.Printf("False negatives: %d\n", result.Overall.FN)
	fmt.Printf("True negatives: %d\n", result.Overall.TN)
	fmt.Printf("Precision: %.1f%%\n", result.Overall.Precision*100)
	fmt.Printf("Recall: %.1f%%\n", result.Overall.Recall*100)
	fmt.Printf("F1: %.1f%%\n", result.Overall.F1*100)
}
