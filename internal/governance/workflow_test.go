package governance

import (
	"context"
	"testing"
)

func TestCreateApprovalRequest_NilPool(t *testing.T) {
	req := &ApprovalRequest{RequestType: "finding_transition", ResourceType: "finding", ResourceID: "f-1"}
	err := CreateApprovalRequest(context.Background(), nil, "user-1", "org-1", req)
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestCreateApprovalRequest_NilRequest(t *testing.T) {
	err := CreateApprovalRequest(context.Background(), nil, "user-1", "org-1", nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}
}

func TestGetApprovalRequest_NilPool(t *testing.T) {
	_, err := GetApprovalRequest(context.Background(), nil, "user-1", "org-1", "req-1")
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestListApprovalRequests_NilPool(t *testing.T) {
	_, err := ListApprovalRequests(context.Background(), nil, "user-1", "org-1", "", 10, 0)
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestDecideApproval_NilPool(t *testing.T) {
	err := DecideApproval(context.Background(), nil, "user-1", "org-1", "req-1", "approved", "lgtm")
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestDecideApproval_InvalidDecision(t *testing.T) {
	err := DecideApproval(context.Background(), nil, "user-1", "org-1", "req-1", "maybe", "unsure")
	if err == nil {
		t.Fatal("expected error for invalid decision")
	}
}

func TestExpirePendingApprovals_NilPool(t *testing.T) {
	_, err := ExpirePendingApprovals(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}
