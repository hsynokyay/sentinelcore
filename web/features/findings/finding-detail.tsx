"use client";

import { useState } from "react";
import { FileCode2, Globe, Hash, MessageSquare, ShieldAlert, Wrench } from "lucide-react";
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
import { CVSSPanel } from "./cvss-panel";
import { ClassificationPanel, TagList } from "./classification-panel";
import { MarkdownDescription } from "./markdown-description";
import { EvidenceViewer } from "./evidence-viewer";
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

  const httpMethod = finding.http_method || finding.method;
  const isDast = finding.finding_type === "dast" || !!finding.url;
  const hasCvss = typeof finding.cvss_score === "number" && finding.cvss_score > 0;

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

      {/* CVSS + Classification side by side */}
      <div className={`grid gap-4 ${hasCvss ? "lg:grid-cols-[minmax(0,300px)_1fr]" : "grid-cols-1"}`}>
        {hasCvss && (
          <CVSSPanel score={finding.cvss_score!} vector={finding.cvss_vector} />
        )}
        <ClassificationPanel
          cweId={finding.cwe_id}
          owaspCategory={finding.owasp_category}
          riskScore={finding.risk_score}
          confidence={finding.confidence}
          ruleId={finding.rule_id}
        />
      </div>

      {/* Location card */}
      <LocationPanel
        isDast={isDast}
        url={finding.url}
        method={httpMethod}
        parameter={finding.parameter}
        filePath={finding.file_path}
        lineNumber={finding.line_number}
      />

      {/* Tags */}
      {finding.tags && finding.tags.length > 0 && <TagList tags={finding.tags} />}

      {/* Description card — renders the structured markdown the worker writes */}
      <section className="rounded-lg border border-border bg-surface-1 p-5">
        <h2 className="text-caption text-muted-foreground mb-3 inline-flex items-center gap-1.5">
          <ShieldAlert className="size-3" /> Description
        </h2>
        <MarkdownDescription source={finding.description} />
      </section>

      {/* SAST taint trace — only when present */}
      {finding.taint_paths && finding.taint_paths.length > 0 && (
        <section className="rounded-lg border border-border bg-surface-1 p-5">
          <AnalysisTrace steps={finding.taint_paths} />
        </section>
      )}

      {/* DAST HTTP evidence — captured request/response */}
      {isDast && (
        <section className="rounded-lg border border-border bg-surface-1 p-5">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-caption text-muted-foreground inline-flex items-center gap-1.5">
              <Globe className="size-3" /> HTTP Evidence
            </h2>
            {finding.evidence_size !== undefined && (
              <span className="text-[11px] text-muted-foreground tabular-nums">
                captured · {formatBytes(finding.evidence_size)}
              </span>
            )}
          </div>
          <EvidenceViewer
            rawJSON={finding.evidence}
            size={finding.evidence_size}
            hash={finding.evidence_hash}
          />
        </section>
      )}

      {/* Remediation pack — separate from inline description, when available */}
      {finding.remediation && <RemediationPanel remediation={finding.remediation} />}

      {/* Triage card */}
      <section className="rounded-lg border border-border bg-surface-1 p-5">
        <h2 className="text-caption text-muted-foreground mb-4 inline-flex items-center gap-1.5">
          <Wrench className="size-3" /> Triage
        </h2>
        <div className="grid gap-4 sm:grid-cols-[200px_1fr] sm:items-start">
          <div>
            <Label htmlFor="triage-status">Status</Label>
            <Select
              value={selectedStatus}
              onValueChange={setSelectedStatus}
              itemToStringLabel={(v) => statusLabel[String(v)] ?? String(v).replace(/_/g, " ")}
            >
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

interface LocationPanelProps {
  isDast: boolean;
  url?: string;
  method?: string;
  parameter?: string;
  filePath?: string;
  lineNumber?: number;
}

function LocationPanel({ isDast, url, method, parameter, filePath, lineNumber }: LocationPanelProps) {
  if (isDast && url) {
    return (
      <section className="rounded-lg border border-border bg-surface-1 p-5">
        <h2 className="text-caption text-muted-foreground mb-3 inline-flex items-center gap-1.5">
          <Globe className="size-3" /> Location
        </h2>
        <div className="flex items-center gap-2 text-body-sm font-mono">
          <span className="px-2 py-0.5 rounded bg-surface-2 text-foreground font-semibold text-xs border border-border-subtle">
            {(method || "GET").toUpperCase()}
          </span>
          <a
            href={url}
            target="_blank"
            rel="noreferrer noopener"
            className="text-primary hover:underline break-all"
          >
            {url}
          </a>
        </div>
        {parameter && (
          <div className="flex items-center gap-2 mt-3 text-xs">
            <span className="text-muted-foreground inline-flex items-center gap-1">
              <Hash className="h-3 w-3" />
              Parameter
            </span>
            <code className="px-1.5 py-0.5 rounded bg-surface-2 border border-border-subtle font-mono">
              {parameter}
            </code>
          </div>
        )}
      </section>
    );
  }

  if (filePath) {
    return (
      <section className="rounded-lg border border-border bg-surface-1 p-5">
        <h2 className="text-caption text-muted-foreground mb-3 inline-flex items-center gap-1.5">
          <FileCode2 className="size-3" /> Location
        </h2>
        <code className="block text-body-sm font-mono bg-surface-2 border border-border-subtle text-foreground px-3 py-2 rounded-md overflow-x-auto">
          {filePath}
          {lineNumber ? `:${lineNumber}` : ""}
        </code>
      </section>
    );
  }

  return null;
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}
