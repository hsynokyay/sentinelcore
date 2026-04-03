import { api } from "@/lib/api-client";
import type { AuditEvent, ComplianceStatus, TriageMetrics } from "@/lib/types";

export async function getComplianceStatus(): Promise<ComplianceStatus> {
  return api.get<ComplianceStatus>("/api/v1/reports/compliance-status");
}

export async function getTriageMetrics(): Promise<TriageMetrics> {
  return api.get<TriageMetrics>("/api/v1/reports/triage-metrics");
}

export interface AuditFilters {
  action?: string;
  actor_id?: string;
  resource_type?: string;
  date_from?: string;
  date_to?: string;
  limit?: number;
  offset?: number;
}

export interface AuditEventsResponse {
  events: AuditEvent[];
  limit: number;
  offset: number;
}

export async function getAuditEvents(filters: AuditFilters = {}): Promise<AuditEventsResponse> {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([k, v]) => {
    if (v !== undefined && v !== "") params.set(k, String(v));
  });
  return api.get<AuditEventsResponse>(`/api/v1/audit?${params.toString()}`);
}

export interface AuditData {
  compliance: ComplianceStatus;
  triage: TriageMetrics;
}

export async function getAuditData(): Promise<AuditData> {
  const [compliance, triage] = await Promise.all([
    getComplianceStatus(),
    getTriageMetrics(),
  ]);
  return { compliance, triage };
}
