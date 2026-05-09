"use client";

import { useState } from "react";
import { SeverityBadge } from "@/components/badges/severity-badge";
import { StatusBadge } from "@/components/badges/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useTriageFinding } from "./hooks";
import { AnalysisTrace } from "./analysis-trace";
import { RemediationPanel } from "./remediation-panel";
import { DeveloperHandoff } from "./developer-handoff";
import { ExportFindingButton } from "@/features/export/export-finding-button";
import { ExportFindingSarifButton } from "@/features/export/export-sarif-buttons";
import { ControlsStrip } from "@/features/compliance/controls-strip";
import type { Finding } from "@/lib/types";

const triageStatuses = [
  "new",
  "confirmed",
  "in_progress",
  "mitigated",
  "resolved",
  "accepted_risk",
  "false_positive",
];

interface FindingDetailProps {
  finding: Finding;
}

export function FindingDetail({ finding }: FindingDetailProps) {
  const [selectedStatus, setSelectedStatus] = useState(finding.status);
  const [reason, setReason] = useState("");
  const triage = useTriageFinding();

  const handleTriage = () => {
    if (!reason.trim()) return;
    triage.mutate({ id: finding.id, status: selectedStatus, reason });
  };

  const location = finding.file_path
    ? `${finding.file_path}${finding.line_number ? `:${finding.line_number}` : ""}`
    : finding.url
      ? `${finding.method || "GET"} ${finding.url}${finding.parameter ? ` (param: ${finding.parameter})` : ""}`
      : "Unknown";

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h2 className="text-xl font-semibold tracking-tight mb-3">{finding.title}</h2>
        <div className="flex items-center gap-2 flex-wrap">
          <SeverityBadge severity={finding.severity} />
          <StatusBadge status={finding.status} />
          <Badge variant="outline" className="text-xs uppercase">
            {finding.finding_type}
          </Badge>
          <div className="ml-auto flex items-center gap-1.5">
            <ExportFindingButton finding={finding} />
            <ExportFindingSarifButton finding={finding} />
          </div>
        </div>
      </div>

      {/* Description */}
      <section>
        <h3 className="text-sm font-medium text-muted-foreground mb-2">Description</h3>
        <p className="text-sm text-foreground leading-relaxed">
          {finding.description || "No description available."}
        </p>
      </section>

      {/* Location */}
      <section>
        <h3 className="text-sm font-medium text-muted-foreground mb-2">Location</h3>
        <code className="text-sm bg-muted px-2 py-1 rounded font-mono">{location}</code>
      </section>

      {/* Phase-5 governance ops: compliance controls strip */}
      <ControlsStrip finding={finding} />

      {/* Analysis Trace — SAST evidence chain */}
      {finding.taint_paths && finding.taint_paths.length > 0 && (
        <AnalysisTrace steps={finding.taint_paths} />
      )}

      {/* Evidence placeholder for findings without a trace */}
      {(!finding.taint_paths || finding.taint_paths.length === 0) && (
        <section>
          <h3 className="text-sm font-medium text-muted-foreground mb-2">Evidence</h3>
          <div className="border rounded-lg p-4 bg-muted/30">
            <p className="text-sm text-muted-foreground italic">
              Evidence details will appear here when the finding has an
              analysis trace.
            </p>
          </div>
        </section>
      )}

      {/* Remediation guidance */}
      {finding.remediation && (
        <RemediationPanel remediation={finding.remediation} />
      )}

      {/* Timeline */}
      <section>
        <h3 className="text-sm font-medium text-muted-foreground mb-2">Timeline</h3>
        <div className="border rounded-lg p-4 bg-muted/30">
          <div className="flex items-center gap-2 text-sm">
            <span className="text-muted-foreground">Created:</span>
            <span>{new Date(finding.created_at).toLocaleString()}</span>
          </div>
        </div>
      </section>

      {/* Correlation */}
      <section>
        <h3 className="text-sm font-medium text-muted-foreground mb-2">Correlation</h3>
        <div className="border rounded-lg p-4 bg-muted/30">
          <p className="text-sm text-muted-foreground italic">
            Related findings and correlations will appear here.
          </p>
        </div>
      </section>

      {/* Triage Actions */}
      <section className="border-t pt-6">
        <h3 className="text-sm font-medium text-muted-foreground mb-3">Triage</h3>
        <div className="space-y-3">
          <div>
            <label className="text-sm font-medium block mb-1">Status</label>
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="w-full max-w-xs border rounded-md px-3 py-2 text-sm bg-background"
            >
              {triageStatuses.map((s) => (
                <option key={s} value={s}>
                  {s.replace(/_/g, " ")}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-sm font-medium block mb-1">Reason</label>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Provide a reason for this status change..."
              className="w-full max-w-md border rounded-md px-3 py-2 text-sm bg-background min-h-[80px]"
            />
          </div>
          <Button
            onClick={handleTriage}
            disabled={!reason.trim() || triage.isPending || selectedStatus === finding.status}
          >
            {triage.isPending ? "Updating..." : "Update Status"}
          </Button>
          {triage.isError && (
            <p className="text-sm text-destructive">
              Failed to update status. Please try again.
            </p>
          )}
        </div>
      </section>
    </div>
  );
}
