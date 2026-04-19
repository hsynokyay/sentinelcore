"use client";

import Link from "next/link";
import { useState, useMemo } from "react";
import { CheckCircle, RotateCcw } from "lucide-react";
import { SeverityBadge } from "@/components/badges/severity-badge";
import { StatusBadge } from "@/components/badges/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScoreDisplay } from "@/components/security/score-display";
import { useRegisterCommands, type DynamicCommand } from "@/components/layout/command-provider";
import { lifecycleState } from "@/lib/security/lifecycle";
import { RiskEvidencePanel } from "./risk-evidence-panel";
import { RiskNextBestAction } from "./risk-next-best-action";
import { useResolveRisk, useReopenRisk } from "./hooks";
import type { RiskClusterDetail } from "@/lib/types";

const roleColors: Record<string, string> = {
  sast: "bg-violet-100 text-violet-800",
  dast: "bg-cyan-100 text-cyan-800",
  sca: "bg-amber-100 text-amber-800",
};

function formatConfidence(c: number): string {
  return `${Math.round(c * 100)}%`;
}

function formatDate(s: string | null | undefined): string {
  if (!s) return "—";
  return new Date(s).toLocaleString();
}

export function RiskDetail({ risk }: { risk: RiskClusterDetail }) {
  const resolve = useResolveRisk();
  const reopen = useReopenRisk();
  const [reason, setReason] = useState("");
  const busy = resolve.isPending || reopen.isPending;

  const canResolve = risk.status === "active" || risk.status === "auto_resolved";
  const canReopen = risk.status === "user_resolved" || risk.status === "muted";

  // Visual state for the score ring. Glow is earned: only critical-severity
  // active clusters receive the halo (Level 3+ in the intensity model).
  const scoreState = lifecycleState(risk.status);
  const showGlow = risk.severity === "critical" && scoreState === "active";

  // Register contextual palette commands for this risk. The commands
  // change based on the risk's lifecycle state — resolve for active,
  // reopen for resolved/muted. Mute is always available for active risks.
  const riskActions = useMemo((): DynamicCommand[] => {
    const cmds: DynamicCommand[] = [];
    if (canResolve) {
      cmds.push({
        id: `risk-resolve-${risk.id}`,
        label: `Resolve "${risk.title}"`,
        group: "Context",
        icon: CheckCircle,
        onSelect: () => resolve.mutate({ id: risk.id }),
        keywords: ["resolve", "close", "fix"],
      });
      // Mute command omitted — requires a duration picker that doesn't
      // exist in the palette yet. Wire when mute UI is added.
    }
    if (canReopen) {
      cmds.push({
        id: `risk-reopen-${risk.id}`,
        label: `Reopen "${risk.title}"`,
        group: "Context",
        icon: RotateCcw,
        onSelect: () => reopen.mutate(risk.id),
        keywords: ["reopen", "reactivate"],
      });
    }
    return cmds;
  }, [risk.id, risk.title, canResolve, canReopen, resolve, reopen]);
  useRegisterCommands(riskActions);

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <section className="flex items-start justify-between gap-6">
        <div className="min-w-0 flex-1">
          <h1 className="text-2xl font-semibold text-foreground truncate">{risk.title}</h1>
          <div className="mt-2 flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={risk.severity} />
            <StatusBadge status={risk.status} />
            <Badge variant="outline" className="text-xs">
              {risk.vuln_class.replace(/_/g, " ")}
            </Badge>
            {risk.cwe_id > 0 && (
              <Badge variant="outline" className="text-xs">
                CWE-{risk.cwe_id}
              </Badge>
            )}
            <Badge variant="outline" className="text-xs uppercase">
              {risk.exposure}
            </Badge>
          </div>
        </div>
        <div className="flex flex-col items-end gap-4 shrink-0">
          <ScoreDisplay
            score={risk.risk_score}
            severity={risk.severity}
            variant="hero"
            state={scoreState}
            glow={showGlow}
          />
          {(canResolve || canReopen) && (
            <div className="flex gap-2">
              {canResolve && (
                <Button
                  disabled={busy}
                  onClick={() => resolve.mutate({ id: risk.id, reason })}
                >
                  Resolve
                </Button>
              )}
              {canReopen && (
                <Button
                  variant="outline"
                  disabled={busy}
                  onClick={() => reopen.mutate(risk.id)}
                >
                  Reopen
                </Button>
              )}
            </div>
          )}
        </div>
      </section>

      {/* Next best action — derived from severity + signals. Skips itself
          for resolved/muted risks. Sits between the header and the
          resolution reason input so the user reads the recommendation
          before deciding to type a resolution rationale. */}
      <RiskNextBestAction risk={risk} />

      {canResolve && (
        <input
          type="text"
          className="w-full rounded border bg-background px-3 py-2 text-sm"
          placeholder="Resolution reason (optional)"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
      )}

      {/* Evidence */}
      <RiskEvidencePanel evidence={risk.evidence} severity={risk.severity} />

      {/* Findings */}
      <section className="rounded-lg border bg-card p-4">
        <h2 className="mb-3 text-sm font-semibold">
          Findings in this risk ({risk.findings.length})
        </h2>
        {risk.findings.length === 0 ? (
          <p className="text-xs text-muted-foreground">No findings linked yet.</p>
        ) : (
          <ul className="space-y-2">
            {risk.findings.map((f) => (
              <li key={f.id} className="flex items-center gap-3">
                <Badge className={`text-[10px] uppercase ${roleColors[f.role] ?? ""}`}>
                  {f.role}
                </Badge>
                <Link
                  href={`/findings/${f.id}`}
                  className="flex-1 truncate text-sm hover:underline"
                >
                  {f.title}
                </Link>
                <span className="text-xs text-muted-foreground font-mono truncate max-w-[240px]">
                  {f.file_path
                    ? `${f.file_path}${f.line_start ? `:${f.line_start}` : ""}`
                    : f.url}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Relations */}
      {risk.relations.length > 0 && (
        <section className="rounded-lg border bg-card p-4">
          <h2 className="mb-3 text-sm font-semibold">Related risks</h2>
          <ul className="space-y-2">
            {risk.relations.map((rel) => (
              <li key={rel.id} className="flex items-center justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <Link
                    href={`/risks/${rel.related_cluster_id}`}
                    className="text-sm font-medium hover:underline truncate block"
                  >
                    {rel.related_cluster_title}
                  </Link>
                  <div className="text-xs text-muted-foreground truncate">
                    {rel.rationale}
                  </div>
                </div>
                <div className="flex flex-col items-end gap-1">
                  <Badge variant="outline" className="text-[10px] uppercase">
                    {rel.relation_type.replace(/_/g, " ")}
                  </Badge>
                  <span className="text-xs tabular-nums text-muted-foreground">
                    {formatConfidence(rel.confidence)}
                  </span>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Context */}
      <section className="rounded-lg border bg-card p-4">
        <h2 className="mb-3 text-sm font-semibold">Context</h2>
        <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
          <dt className="text-muted-foreground">Kind</dt>
          <dd>{risk.fingerprint_kind}</dd>
          {risk.fingerprint_kind === "dast_route" ? (
            <>
              <dt className="text-muted-foreground">Method</dt>
              <dd>{risk.http_method || "—"}</dd>
              <dt className="text-muted-foreground">Route</dt>
              <dd className="font-mono truncate">{risk.canonical_route || "—"}</dd>
              <dt className="text-muted-foreground">Param</dt>
              <dd className="font-mono">{risk.canonical_param || "—"}</dd>
            </>
          ) : (
            <>
              <dt className="text-muted-foreground">Language</dt>
              <dd>{risk.language || "—"}</dd>
              <dt className="text-muted-foreground">File</dt>
              <dd className="font-mono truncate">{risk.file_path || "—"}</dd>
              <dt className="text-muted-foreground">Method</dt>
              <dd className="font-mono">{risk.enclosing_method || "—"}</dd>
            </>
          )}
          <dt className="text-muted-foreground">First seen</dt>
          <dd>{formatDate(risk.first_seen_at)}</dd>
          <dt className="text-muted-foreground">Last seen</dt>
          <dd>{formatDate(risk.last_seen_at)}</dd>
          {risk.resolved_at && (
            <>
              <dt className="text-muted-foreground">Resolved at</dt>
              <dd>{formatDate(risk.resolved_at)}</dd>
            </>
          )}
          {risk.muted_until && (
            <>
              <dt className="text-muted-foreground">Muted until</dt>
              <dd>{formatDate(risk.muted_until)}</dd>
            </>
          )}
        </dl>
      </section>
    </div>
  );
}
