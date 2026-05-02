"use client";

import { Pencil, Trash2 } from "lucide-react";
import { DataTable, type Column } from "@/components/data/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { TrustStrip, type TrustSignal } from "@/components/security/trust-strip";
import type { ScanTarget } from "@/lib/types";

const typeColors: Record<string, string> = {
  web_app: "bg-cyan-100 text-cyan-800",
  api: "bg-emerald-100 text-emerald-800",
  graphql: "bg-fuchsia-100 text-fuchsia-800",
};

/**
 * Build the trust signals for a scan target row. The strip shows up
 * to three facets of the target's trust posture:
 *
 *  1. **Verification** — has the operator proven ownership of this
 *     URL? This is the canonical "is this thing safe to scan" answer.
 *  2. **Scope** — are allowed_domains / allowed_paths set, or is the
 *     target wide-open? A scoped target is verified-but-also-bounded.
 *  3. **Rate limit** — is max_rps set to a sensible value (>0)?
 *     Un-rate-limited scans can knock targets over.
 *
 * Each signal returns its own TrustState. Verified + scoped +
 * rate-limited == fully trustworthy. Pending verification + wide-open
 * scope + no rps cap == "do NOT scan this without a closer look".
 */
function buildTrustSignals(t: ScanTarget): TrustSignal[] {
  const signals: TrustSignal[] = [];

  // 1. Verification status — first because it's the most important read.
  signals.push({
    state: t.verification_status === "verified" ? "verified" : "pending",
    label: t.verification_status === "verified" ? "Verified" : "Pending",
  });

  // 2. Scope — verified state if the target has at least one allowed
  //    domain set, pending otherwise. We don't show "scoped" / "open"
  //    as a label because TrustChip's vocabulary is verified/pending —
  //    the label re-purposes the same shape for a different facet.
  const isScoped = (t.allowed_domains?.length ?? 0) > 0;
  signals.push({
    state: isScoped ? "verified" : "pending",
    label: isScoped ? "Scoped" : "Open scope",
  });

  // 3. Rate limit — verified if max_rps is set and > 0.
  const hasRpsCap = (t.max_rps ?? 0) > 0;
  signals.push({
    state: hasRpsCap ? "verified" : "pending",
    label: hasRpsCap ? `${t.max_rps} rps` : "No rps cap",
  });

  return signals;
}

interface TargetsTableProps {
  targets: ScanTarget[];
  isLoading?: boolean;
  onEdit: (t: ScanTarget) => void;
  onDelete: (t: ScanTarget) => void;
}

export function TargetsTable({
  targets,
  isLoading,
  onEdit,
  onDelete,
}: TargetsTableProps) {
  const columns: Column<ScanTarget>[] = [
    {
      key: "target_type",
      header: "Type",
      className: "w-[110px]",
      render: (t) => (
        <Badge
          variant="outline"
          className={`text-xs ${typeColors[t.target_type] || "bg-gray-100 text-gray-700"}`}
        >
          {t.target_type}
        </Badge>
      ),
    },
    {
      key: "label",
      header: "Label",
      render: (t) => (
        <div className="flex flex-col">
          <span className="font-medium">{t.label || t.base_url}</span>
          {t.environment && (
            <span className="text-xs text-muted-foreground">
              {t.environment}
            </span>
          )}
        </div>
      ),
    },
    {
      key: "base_url",
      header: "Base URL",
      render: (t) => (
        <span className="text-sm font-mono text-muted-foreground truncate block max-w-[340px]">
          {t.base_url}
        </span>
      ),
    },
    {
      // Three trust signals stacked into a strip — verification, scope,
      // and rate-limit. Replaces the old hardcoded green/amber badge AND
      // the standalone Max RPS column, since the strip now carries the
      // rps signal as one of its facets.
      key: "trust",
      header: "Trust",
      className: "w-[260px]",
      render: (t) => (
        <TrustStrip
          aria-label="Target trust signals"
          signals={buildTrustSignals(t)}
          // Overall pulse: green if all three signals are verified,
          // yellow if any are pending. The dot makes the row's overall
          // posture readable without parsing all three chips.
          overallPulse={
            buildTrustSignals(t).every((s) => s.state === "verified")
              ? "ok"
              : "warn"
          }
        />
      ),
    },
    {
      key: "actions",
      header: "",
      className: "w-[96px]",
      render: (t) => (
        <div className="flex items-center gap-1 justify-end">
          <Button
            variant="ghost"
            size="icon"
            aria-label="Edit target"
            onClick={(e) => {
              e.stopPropagation();
              onEdit(t);
            }}
          >
            <Pencil className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            aria-label="Delete target"
            className="text-destructive hover:text-destructive"
            onClick={(e) => {
              e.stopPropagation();
              onDelete(t);
            }}
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      data={targets}
      isLoading={isLoading}
      emptyMessage="No targets yet — click New Target to add one."
    />
  );
}
