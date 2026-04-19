package governance

import (
	"context"
	"testing"
	"time"
)

func TestCreateRetentionRecord_NilPool(t *testing.T) {
	rec := &RetentionRecord{ResourceType: "finding", ResourceID: "f-1"}
	err := CreateRetentionRecord(context.Background(), nil, rec)
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestCreateRetentionRecord_NilRecord(t *testing.T) {
	err := CreateRetentionRecord(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("expected error for nil record")
	}
}

func TestTransitionToArchived_NilPool(t *testing.T) {
	_, err := TransitionToArchived(context.Background(), nil, time.Now())
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestTransitionToPurgePending_NilPool(t *testing.T) {
	_, err := TransitionToPurgePending(context.Background(), nil, time.Now())
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestPurgeRecords_NilPool(t *testing.T) {
	_, err := PurgeRecords(context.Background(), nil, time.Now())
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestSetLegalHold_NilPool(t *testing.T) {
	err := SetLegalHold(context.Background(), nil, "u-1", "org-1", "finding", "f-1", true, "litigation")
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestGetRetentionStats_NilPool(t *testing.T) {
	_, err := GetRetentionStats(context.Background(), nil, "u-1", "org-1")
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestRetentionRecord_LegalHoldField(t *testing.T) {
	rec := RetentionRecord{
		LegalHold: true,
	}
	if !rec.LegalHold {
		t.Fatal("expected LegalHold to be true")
	}
	rec.LegalHold = false
	if rec.LegalHold {
		t.Fatal("expected LegalHold to be false")
	}
}
