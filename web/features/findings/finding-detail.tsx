"use client";

import { useState } from "react";
import { FileCode2, MessageSquare, ShieldAlert, Wrench } from "lucide-react";
import { SeverityBadge } from "@/components/badges/severity-badge";
import { StatusBadge } from "@/components/badges/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import { useTriageFinding } from "./hooks";
import { AnalysisTrace } from "./analysis-trace";
import { RemediationPanel } from "./remediation-panel";
import { ExportFindingButton } from "@/features/export/export-finding-button";
import { ExportFindingSarifButton } from "@/features/export/export-sarif-buttons";
import type { Finding } from "@/lib/types";

const triageStatuses = [
  "new",
  "confirmed",
  "in_progress",
  "mitigated",
  "resolved",
  "accepted_risk",
  "false_positive",
] as const;

const statusLabel: Record<string, string> = {
  new: "New",
  confirmed: "Confirmed",
  in_progress: "In progress",
  mitigated: "Mitigated",
  resolved: "Resolved",
  accepted_risk: "Accepted risk",
  false_positive: "False positive",
};

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
      : null;

  return (
    <div className="space-y-6">
      {/* Title + meta pill row + actions */}
      <header className="space-y-3">
        <h1 className="font-display text-h1 text-foreground tracking-tight">
          {finding.title}
        </h1>
        <div className="flex items-center gap-2 flex-wrap">
          <SeverityBadge severity={finding.severity} />
          <StatusBadge status={finding.status} />
          <Badge variant="outline">{finding.finding_type.toUpperCase()}</Badge>
          {finding.scan_id && (
            <Badge variant="tag">scan #{finding.scan_id.slice(0, 8)}</Badge>
          )}
          <div className="ml-auto flex items-center gap-1.5">
            <ExportFindingButton finding={finding} />
            <ExportFindingSarifButton finding={finding} />
          </div>
        </div>
      </header>

      {/* Description card */}
      <section className="rounded-lg border border-border bg-surface-1 p-5">
        <h2 className="text-caption text-muted-foreground mb-2 inline-flex items-center gap-1.5">
          <ShieldAlert className="size-3" /> Description
        </h2>
        <p className="text-body text-foreground leading-relaxed max-w-prose">
          {finding.description || "No description available."}
        </p>
      </section>

      {/* Location card — only if location is meaningful */}
      {location && (
        <section className="rounded-lg border border-border bg-surface-1 p-5">
          <h2 className="text-caption text-muted-foreground mb-2 inline-flex items-center gap-1.5">
            <FileCode2 className="size-3" /> Location
          </h2>
          <code className="block text-body-sm font-mono bg-surface-2 border border-border-subtle text-foreground px-3 py-2 rounded-md overflow-x-auto">
            {location}
          </code>
        </section>
      )}

      {/* Analysis Trace — only if SAST evidence chain exists */}
      {finding.taint_paths && finding.taint_paths.length > 0 && (
        <section className="rounded-lg border border-border bg-surface-1 p-5">
          <AnalysisTrace steps={finding.taint_paths} />
        </section>
      )}

      {/* Remediation guidance — already a card-styled subtree */}
      {finding.remediation && <RemediationPanel remediation={finding.remediation} />}

      {/* Triage card */}
      <section className="rounded-lg border border-border bg-surface-1 p-5">
        <h2 className="text-caption text-muted-foreground mb-4 inline-flex items-center gap-1.5">
          <Wrench className="size-3" /> Triage
        </h2>
        <div className="grid gap-4 sm:grid-cols-[200px_1fr] sm:items-start">
          <div>
            <Label htmlFor="triage-status">Status</Label>
            <Select value={selectedStatus} onValueChange={setSelectedStatus}>
              <SelectTrigger id="triage-status">
                <SelectValue placeholder="Select status" />
              </SelectTrigger>
              <SelectContent>
                {triageStatuses.map((s) => (
                  <SelectItem key={s} value={s}>
                    {statusLabel[s] ?? s.replace(/_/g, " ")}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label htmlFor="triage-reason" className="inline-flex items-center gap-1.5">
              <MessageSquare className="size-3" /> Reason
            </Label>
            <Textarea
              id="triage-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Why are you changing the status? (audit-trail)"
              className="min-h-[88px]"
            />
          </div>
        </div>
        <div className="mt-4 flex items-center justify-end gap-2">
          {triage.isError && (
            <p className="text-body-sm text-[color:var(--severity-critical)] mr-auto">
              Failed to update — please retry.
            </p>
          )}
          <Button
            onClick={handleTriage}
            disabled={!reason.trim() || triage.isPending || selectedStatus === finding.status}
          >
            {triage.isPending ? "Updating…" : "Update status"}
          </Button>
        </div>
      </section>
    </div>
  );
}
