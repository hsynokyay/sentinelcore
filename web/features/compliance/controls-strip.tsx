"use client";

// Phase-5 governance ops: compliance controls strip for finding-detail.
//
// Pulls CWE-* references off the remediation block and resolves each
// to its merged built-in + tenant control set via the /resolve endpoint.
// Used inline in the finding detail page right under the description.

import { Badge } from "@/components/ui/badge";

import { useResolveControls } from "./hooks";
import type { Finding } from "@/lib/types";

interface ControlsStripProps {
  finding: Finding;
}

function extractCWEID(refTitle: string): number | null {
  const m = /^CWE-(\d+)$/i.exec(refTitle.trim());
  if (!m) return null;
  const n = parseInt(m[1], 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

export function ControlsStrip({ finding }: ControlsStripProps) {
  const refs = finding.remediation?.references ?? [];
  const cweID = refs
    .map((r) => extractCWEID(r.title))
    .find((n): n is number => n !== null);

  const { data, isLoading } = useResolveControls(cweID);

  if (!cweID) return null;
  if (isLoading) {
    return (
      <section>
        <h3 className="text-sm font-medium text-muted-foreground mb-2">Compliance</h3>
        <p className="text-xs text-muted-foreground">Resolving controls…</p>
      </section>
    );
  }
  if (!data || data.length === 0) return null;

  return (
    <section>
      <h3 className="text-sm font-medium text-muted-foreground mb-2">
        Compliance{" "}
        <span className="text-xs font-normal text-muted-foreground/70">
          (CWE-{cweID})
        </span>
      </h3>
      <div className="flex flex-wrap gap-2">
        {data.map((c) => (
          <span
            key={`${c.catalog_code}/${c.control_id}`}
            className="inline-flex items-center gap-2 px-2.5 py-1 border rounded-md bg-muted/30 text-xs"
            title={`${c.catalog_name} — ${c.title}`}
          >
            <span className="font-mono font-medium">
              {c.catalog_code.split("_")[0]}:{c.control_id}
            </span>
            <span className="text-muted-foreground hidden md:inline">
              {c.title.length > 40 ? `${c.title.slice(0, 37)}…` : c.title}
            </span>
            <Badge variant={c.confidence === "custom" ? "status" : "tag"} className="text-[10px]">
              {c.confidence}
            </Badge>
          </span>
        ))}
      </div>
    </section>
  );
}
