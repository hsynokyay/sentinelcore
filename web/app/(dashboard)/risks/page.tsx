"use client";

import { useState, useMemo, useEffect } from "react";
import { PageHeader } from "@/components/data/page-header";
import { ErrorState } from "@/components/data/error-state";
import { RisksTable } from "@/features/risks/risks-table";
import { useRisks } from "@/features/risks/hooks";
import { useProjects } from "@/features/scans/hooks";
import type { RiskStatus } from "@/lib/types";

type StatusFilter = RiskStatus | "all";

const statusTabs: { id: StatusFilter; label: string }[] = [
  { id: "active", label: "Active" },
  { id: "user_resolved", label: "Resolved" },
  { id: "muted", label: "Muted" },
  { id: "auto_resolved", label: "Auto-resolved" },
  { id: "all", label: "All" },
];

export default function RisksPage() {
  const { data: projectsData } = useProjects();
  const projects = useMemo(() => projectsData?.projects ?? [], [projectsData]);
  const [projectId, setProjectId] = useState<string>("");
  const [status, setStatus] = useState<StatusFilter>("active");

  useEffect(() => {
    if (!projectId && projects.length > 0) {
      setProjectId(projects[0].id);
    }
  }, [projects, projectId]);

  const { data, isLoading, isError, refetch } = useRisks({
    project_id: projectId,
    status,
    limit: 50,
  });

  return (
    <div>
      <PageHeader
        title="Risks"
        description="Explainable risk clusters correlated from SAST, DAST, and attack surface."
      />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <select
          className="rounded border bg-background px-3 py-1.5 text-sm"
          value={projectId}
          onChange={(e) => setProjectId(e.target.value)}
        >
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.display_name || p.name}
            </option>
          ))}
        </select>

        <div className="flex gap-1 rounded-lg border bg-background p-1">
          {statusTabs.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setStatus(t.id)}
              className={`rounded-md px-3 py-1 text-sm ${
                status === t.id
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:bg-accent"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {isError ? (
        <ErrorState message="Failed to load risks" onRetry={() => refetch()} />
      ) : (
        <RisksTable data={data?.risks ?? []} isLoading={isLoading} />
      )}
    </div>
  );
}
