// Auth
export interface LoginRequest {
  email: string;
  password: string;
}
export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
}

// Core entities
export interface User {
  id: string;
  email: string;
  full_name: string;
  role: string;
  org_id: string;
  status: string;
  created_at: string;
}
export interface Organization {
  id: string;
  name: string;
  display_name: string;
  status: string;
  created_at: string;
}
export interface Team {
  id: string;
  org_id: string;
  name: string;
  display_name: string;
  created_at: string;
}
export interface Project {
  id: string;
  org_id: string;
  team_id: string;
  name: string;
  display_name: string;
  description: string;
  status: string;
  created_at: string;
}

// Findings
export interface Finding {
  id: string;
  project_id: string;
  scan_id: string;
  finding_type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: string;
  title: string;
  description: string;
  file_path?: string;
  line_number?: number;
  url?: string;
  method?: string;
  parameter?: string;
  created_at: string;
}
export interface FindingsResponse {
  findings: Finding[];
  limit: number;
  offset: number;
}

// Scans
export interface Scan {
  id: string;
  project_id: string;
  scan_type: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  progress: number;
  target_id: string;
  created_at: string;
  started_at?: string;
  finished_at?: string;
}

// Governance
export interface ApprovalRequest {
  id: string;
  org_id: string;
  team_id?: string;
  request_type: string;
  resource_type: string;
  resource_id: string;
  requested_by: string;
  reason: string;
  status: "pending" | "approved" | "rejected" | "expired";
  decided_by?: string;
  decision_reason?: string;
  decided_at?: string;
  expires_at?: string;
  created_at: string;
}

export interface EmergencyStop {
  id: string;
  org_id: string;
  scope: string;
  scope_id?: string;
  reason: string;
  activated_by: string;
  activated_at: string;
  deactivated_by?: string;
  deactivated_at?: string;
  active: boolean;
}

export interface OrgSettings {
  org_id: string;
  require_approval_for_risk_acceptance: boolean;
  require_approval_for_false_positive: boolean;
  default_finding_sla_days: Record<string, number>;
  retention_policies: Record<
    string,
    { retention_days: number; grace_days: number }
  >;
}

// Notifications
export interface Notification {
  id: string;
  org_id: string;
  user_id: string;
  category: string;
  title: string;
  body?: string;
  resource_type?: string;
  resource_id?: string;
  read: boolean;
  created_at: string;
}

// Reports
export interface FindingSummaryItem {
  severity: string;
  status: string;
  finding_type: string;
  count: number;
}
export interface TriageMetrics {
  open_findings: number;
  closed_findings: number;
  assigned_findings: number;
  sla_compliant: number;
  sla_violated: number;
}
export interface ComplianceStatus {
  audit_log_count: number;
  sla_compliance_pct: number;
  findings_within_sla: number;
  findings_breached_sla: number;
}

// Surface
export interface SurfaceEntry {
  id: string;
  type: "route" | "form" | "api_endpoint" | "clickable";
  url: string;
  method: string;
  exposure: "public" | "authenticated" | "both" | "unknown";
  title?: string;
  finding_ids?: string[];
  observation_count: number;
  first_seen_at: string;
  last_seen_at: string;
  scan_count: number;
}

// Audit
export interface AuditEvent {
  event_id: string;
  timestamp: string;
  actor_type: string;
  actor_id: string;
  action: string;
  resource_type: string;
  resource_id: string;
  result: string;
  details?: unknown;
}
