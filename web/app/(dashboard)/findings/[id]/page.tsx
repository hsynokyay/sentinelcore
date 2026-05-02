"use client";

import { use } from "react";
import Link from "next/link";
import { ChevronLeft } from "lucide-react";
import { DetailShell } from "@/components/data/detail-shell";
import { LoadingState } from "@/components/data/loading-state";
import { ErrorState } from "@/components/data/error-state";
import { Button } from "@/components/ui/button";
import { FindingDetail } from "@/features/findings/finding-detail";
import { useFinding } from "@/features/findings/hooks";

function formatDate(s: string | null | undefined): string {
  if (!s) return "—";
  return new Date(s).toLocaleDateString();
}

export default function FindingDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const { data, isLoading, isError, refetch } = useFinding(id);

  const f = data?.finding;

  const location = f
    ? f.file_path
      ? `${f.file_path}${f.line_number ? `:${f.line_number}` : ""}`
      : f.url
        ? `${f.method || "GET"} ${f.url}`
        : "—"
    : "—";

  return (
    <div>
      <div className="mb-4">
        <Link href="/findings">
          <Button variant="ghost" size="sm" className="-ml-2">
            <ChevronLeft className="h-4 w-4 mr-1" /> Back to Findings
          </Button>
        </Link>
      </div>

      {isLoading && <LoadingState rows={6} />}
      {isError && <ErrorState message="Failed to load finding" onRetry={() => refetch()} />}
      {f && (
        <DetailShell
          leftRail={
            // Quick metadata — severity/status/type live in the main header
            // (right next to the finding title where they're most useful);
            // the rail is for the smaller "where it lives" facts.
            <div className="space-y-1.5">
              <h3 className="text-caption text-muted-foreground mb-2">Quick info</h3>
              <dl className="space-y-2 text-body-sm">
                <div className="flex items-center justify-between gap-2">
                  <dt className="text-muted-foreground shrink-0">Scan</dt>
                  <dd className="font-mono text-mono">#{f.scan_id?.slice(0, 8) ?? "—"}</dd>
                </div>
                <div className="flex items-start justify-between gap-2">
                  <dt className="text-muted-foreground shrink-0">Location</dt>
                  <dd className="font-mono text-mono text-right truncate max-w-[140px]" title={location}>
                    {location}
                  </dd>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <dt className="text-muted-foreground shrink-0">Reported</dt>
                  <dd className="tabular-nums">{formatDate(f.created_at)}</dd>
                </div>
                {f.cwe_id && (
                  <div className="flex items-center justify-between gap-2">
                    <dt className="text-muted-foreground shrink-0">CWE</dt>
                    <dd className="font-mono text-mono">CWE-{f.cwe_id}</dd>
                  </div>
                )}
                {f.rule_id && (
                  <div className="flex items-start justify-between gap-2">
                    <dt className="text-muted-foreground shrink-0">Rule</dt>
                    <dd className="font-mono text-mono text-right truncate max-w-[140px]" title={f.rule_id}>
                      {f.rule_id}
                    </dd>
                  </div>
                )}
              </dl>
            </div>
          }
          main={<FindingDetail finding={f} />}
        />
      )}
    </div>
  );
}
