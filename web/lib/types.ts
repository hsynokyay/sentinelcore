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
  taint_paths?: TaintPathStep[];
  rule_id?: string;
  remediation?: RemediationBlock;
}

export interface RemediationBlock {
  title: string;
  summary: string;
  why_it_matters: string;
  how_to_fix: string;
  unsafe_example: string;
  safe_example: string;
  developer_notes?: string;
  verification_checklist: string[];
  references: RemediationRef[];
}

export interface RemediationRef {
  title: string;
  url: string;
}

export interface TaintPathStep {
  step_index: number;
  file_path: string;
  line_start: number;
  line_end?: number;
  step_kind: "source" | "propagation" | "sink";
  detail: string;
  function_fqn?: string;
}
export interface FindingsResponse {
  findings: Finding[];
  limit: number;
  offset: number;
}

// Scan Targets
export type TargetType = "web_app" | "api" | "graphql";

export interface ScanTarget {
  id: string;
  project_id: string;
  target_type: TargetType;
  base_url: string;
  allowed_domains: string[];
  allowed_paths?: string[];
  excluded_paths?: string[];
  allowed_ports: number[];
  max_rps: number;
  label?: string;
  environment?: string;
  notes?: string;
  auth_config_id?: string;
  verification_status: "pending" | "verified";
  created_at: string;
  updated_at: string;
  verified_at?: string;
}

export interface CreateScanTargetPayload {
  target_type: TargetType;
  base_url: string;
  allowed_domains?: string[];
  allowed_paths?: string[];
  excluded_paths?: string[];
  allowed_ports?: number[];
  max_rps?: number;
  label?: string;
  environment?: string;
  notes?: string;
  auth_config_id?: string;
}

// Auth profiles (DAST credentials)
export type AuthProfileType = "bearer_token" | "api_key" | "basic_auth";

export interface AuthProfile {
  id: string;
  project_id: string;
  name: string;
  auth_type: AuthProfileType;
  description?: string;
  metadata: Record<string, unknown>;
  has_credentials: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface CreateAuthProfilePayload {
  name: string;
  auth_type: AuthProfileType;
  description?: string;
  // bearer_token
  token?: string;
  token_prefix?: string;
  // api_key
  api_key?: string;
  header_name?: string;
  query_name?: string;
  // basic_auth
  username?: string;
  password?: string;
  // optional endpoint URL (form login, etc.)
  endpoint_url?: string;
}

// Scans
export type ScanStatus =
  | "pending"
  | "queued"
  | "scope_validating"
  | "dispatched"
  | "running"
  | "collecting"
  | "correlating"
  | "completed"
  | "failed"
  | "cancelled"
  | "timed_out";

export interface Scan {
  id: string;
  project_id: string;
  project_name?: string;
  scan_type: "sast" | "dast" | "full";
  scan_profile?: "passive" | "standard" | "aggressive";
  trigger_type?: "manual" | "scheduled" | "cicd" | "rescan" | "api";
  status: ScanStatus;
  progress: number;
  progress_phase?: string;
  target_id?: string;
  target_label?: string;
  target_base_url?: string;
  source_artifact_id?: string;
  source_artifact_name?: string;
  auth_profile_id?: string;
  auth_profile_name?: string;
  auth_profile_type?: string;
  created_by?: string;
  created_at: string;
  started_at?: string;
  finished_at?: string;
  error_message?: string;
}

// Source artifacts (SAST)
export interface SourceArtifact {
  id: string;
  project_id: string;
  name: string;
  description?: string;
  format: "zip";
  size_bytes: number;
  sha256: string;
  entry_count: number;
  uncompressed_size: number;
  uploaded_by: string;
  created_at: string;
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
  retention_active: number;
  retention_archived: number;
  retention_purged: number;
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

// Scans response
export interface ScansResponse {
  scans: Scan[];
  limit: number;
  offset: number;
}

// Approvals response
export interface ApprovalsResponse {
  approvals: ApprovalRequest[];
  limit: number;
  offset: number;
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

// ---------- Risk Correlation ----------
export type RiskStatus = 'active' | 'auto_resolved' | 'user_resolved' | 'muted';
export type RiskExposure = 'public' | 'authenticated' | 'both' | 'unknown';
export type RiskFingerprintKind = 'dast_route' | 'sast_file';
export type RiskSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface RiskReason {
  code: string;
  label: string;
  weight: number | null;
}

export interface RiskCluster {
  id: string;
  title: string;
  vuln_class: string;
  cwe_id: number;
  severity: RiskSeverity;
  risk_score: number;
  exposure: RiskExposure;
  status: RiskStatus;
  finding_count: number;
  surface_count: number;
  first_seen_at: string;
  last_seen_at: string;
  top_reasons: RiskReason[] | null;
}

export interface RiskEvidence {
  category: 'score_base' | 'score_boost' | 'score_penalty' | 'link' | 'context';
  code: string;
  label: string;
  weight: number | null;
  ref_type: string;
  ref_id: string;
  sort_order: number;
}

export interface RiskMemberFinding {
  id: string;
  role: 'sast' | 'dast' | 'sca';
  title: string;
  severity: string;
  file_path: string;
  url: string;
  line_start: number | null;
}

export interface RiskRelation {
  id: string;
  related_cluster_id: string;
  relation_type: 'runtime_confirmation' | 'same_cwe' | 'related_surface';
  confidence: number;
  rationale: string;
  related_cluster_title: string;
}

export interface RiskClusterDetail extends RiskCluster {
  project_id: string;
  owasp_category?: string;
  fingerprint_kind: RiskFingerprintKind;
  canonical_route?: string;
  http_method?: string;
  canonical_param?: string;
  language?: string;
  file_path?: string;
  enclosing_method?: string;
  last_run_id?: string | null;
  resolved_at?: string | null;
  resolution_reason?: string;
  muted_until?: string | null;
  evidence: RiskEvidence[];
  findings: RiskMemberFinding[];
  relations: RiskRelation[];
}

export interface RiskListResponse {
  risks: RiskCluster[];
  total: number;
  limit: number;
  offset: number;
}

export interface RiskListFilters {
  project_id: string;
  status?: RiskStatus | 'all';
  severity?: string;
  vuln_class?: string;
  limit?: number;
  offset?: number;
}
