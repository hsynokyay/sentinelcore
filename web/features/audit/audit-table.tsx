"use client";

import type { AuditData } from "./api";

interface StatCardProps {
  label: string;
  value: string | number;
  description?: string;
}

function StatCard({ label, value, description }: StatCardProps) {
  return (
    <div className="border rounded-lg p-4">
      <p className="text-xs text-muted-foreground font-medium uppercase tracking-wide">{label}</p>
      <p className="text-2xl font-semibold mt-1">{value}</p>
      {description && <p className="text-xs text-muted-foreground mt-1">{description}</p>}
    </div>
  );
}

interface AuditTableProps {
  data: AuditData;
}

export function AuditTable({ data }: AuditTableProps) {
  const { compliance, triage } = data;

  return (
    <div className="space-y-8">
      {/* Compliance Metrics */}
      <section>
        <h3 className="text-sm font-medium text-muted-foreground mb-4">Compliance</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard
            label="SLA Compliance"
            value={`${compliance.sla_compliance_pct.toFixed(1)}%`}
            description="Overall SLA adherence"
          />
          <StatCard
            label="Within SLA"
            value={compliance.findings_within_sla}
            description="Findings resolved in time"
          />
          <StatCard
            label="SLA Breached"
            value={compliance.findings_breached_sla}
            description="Findings past deadline"
          />
          <StatCard
            label="Audit Events"
            value={compliance.audit_log_count}
            description="Total logged events"
          />
        </div>
      </section>

      {/* Triage Metrics */}
      <section>
        <h3 className="text-sm font-medium text-muted-foreground mb-4">Triage</h3>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <StatCard label="Open" value={triage.open_findings} />
          <StatCard label="Closed" value={triage.closed_findings} />
          <StatCard label="Assigned" value={triage.assigned_findings} />
          <StatCard label="SLA Compliant" value={triage.sla_compliant} />
          <StatCard label="SLA Violated" value={triage.sla_violated} />
        </div>
      </section>
    </div>
  );
}
