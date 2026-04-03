import { api } from "@/lib/api-client";
import type { ComplianceStatus, TriageMetrics } from "@/lib/types";

export async function getComplianceStatus(): Promise<ComplianceStatus> {
  return api.get<ComplianceStatus>("/api/v1/reports/compliance");
}

export async function getTriageMetrics(): Promise<TriageMetrics> {
  return api.get<TriageMetrics>("/api/v1/reports/triage-metrics");
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
