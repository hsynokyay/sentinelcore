package audit

// AuditEvent represents a single auditable action in the system.
type AuditEvent struct {
	EventID      string `json:"event_id"`
	Timestamp    string `json:"timestamp"`
	ActorType    string `json:"actor_type"`
	ActorID      string `json:"actor_id"`
	ActorIP      string `json:"actor_ip,omitempty"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	OrgID        string `json:"org_id,omitempty"`
	TeamID       string `json:"team_id,omitempty"`
	ProjectID    string `json:"project_id,omitempty"`
	Details      any    `json:"details,omitempty"`
	Result       string `json:"result"`
}
