"use client";

import { useState } from "react";
import { Globe, FileCode, Hash } from "lucide-react";
import { SeverityBadge } from "@/components/badges/severity-badge";
import { StatusBadge } from "@/components/badges/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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

  const httpMethod = finding.http_method || finding.method;
  const isDast = finding.finding_type === "dast" || !!finding.url;
  const hasCvss = typeof finding.cvss_score === "number" && finding.cvss_score > 0;

  return (
    <div className="space-y-6">
      {/* ------- Header ------- */}
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

      {/* ------- CVSS + Classification side by side ------- */}
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

      {/* ------- Location ------- */}
      <LocationPanel
        isDast={isDast}
        url={finding.url}
        method={httpMethod}
        parameter={finding.parameter}
        filePath={finding.file_path}
        lineNumber={finding.line_number}
      />

      {/* ------- Tags ------- */}
      {finding.tags && finding.tags.length > 0 && <TagList tags={finding.tags} />}

      {/* ------- Description (markdown sections) ------- */}
      <section className="rounded-lg border bg-card p-5 space-y-1">
        <MarkdownDescription source={finding.description} />
      </section>

      {/* ------- SAST taint trace ------- */}
      {finding.taint_paths && finding.taint_paths.length > 0 && (
        <AnalysisTrace steps={finding.taint_paths} />
      )}

      {/* ------- DAST HTTP evidence ------- */}
      {isDast && (
        <section>
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-muted-foreground">
              HTTP Evidence
            </h3>
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

      {/* ------- Remediation pack (separate from description) ------- */}
      {finding.remediation && <RemediationPanel remediation={finding.remediation} />}

      {/* ------- Timeline ------- */}
      <section>
        <h3 className="text-sm font-medium text-muted-foreground mb-2">Timeline</h3>
        <div className="rounded-lg border p-4 bg-muted/20">
          <div className="flex items-center gap-2 text-sm">
            <span className="text-muted-foreground">Created:</span>
            <span>{new Date(finding.created_at).toLocaleString()}</span>
          </div>
        </div>
      </section>

      {/* ------- Triage ------- */}
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
      <div className="rounded-lg border bg-card p-4">
        <h4 className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground mb-3 flex items-center gap-1.5">
          <Globe className="h-3 w-3" />
          Location
        </h4>
        <div className="flex items-center gap-2 text-sm font-mono">
          <span className="px-2 py-0.5 rounded bg-muted text-foreground font-semibold text-xs">
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
          <div className="flex items-center gap-2 mt-2.5 text-xs">
            <span className="text-muted-foreground inline-flex items-center gap-1">
              <Hash className="h-3 w-3" />
              Parameter
            </span>
            <code className="px-1.5 py-0.5 rounded bg-muted border font-mono">{parameter}</code>
          </div>
        )}
      </div>
    );
  }

  if (filePath) {
    return (
      <div className="rounded-lg border bg-card p-4">
        <h4 className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground mb-3 flex items-center gap-1.5">
          <FileCode className="h-3 w-3" />
          Location
        </h4>
        <code className="text-sm font-mono break-all">
          {filePath}
          {lineNumber ? `:${lineNumber}` : ""}
        </code>
      </div>
    );
  }

  return null;
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}
