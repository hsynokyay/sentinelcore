"use client";

// Phase-5 governance ops: per-project SLA policy editor.
//
// Loads the existing override (if any) for a project, lets a security_admin
// edit per-severity SLA-days, saves via PUT /api/v1/governance/sla/policies/{id},
// and offers a "Reset to org default" action that DELETEs the override.

import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { LoadingState } from "@/components/data/loading-state";
import { ErrorState } from "@/components/data/error-state";

import {
  useDeleteProjectSLAPolicy,
  useProjectSLAPolicy,
  usePutProjectSLAPolicy,
  useSettings,
} from "./hooks";

interface SLAPoliciesFormProps {
  projectId: string;
}

const FALLBACK_DAYS: Record<string, number> = {
  critical: 3,
  high: 7,
  medium: 30,
  low: 90,
};

export function SLAPoliciesForm({ projectId }: SLAPoliciesFormProps) {
  const policyQuery = useProjectSLAPolicy(projectId);
  const settingsQuery = useSettings();
  const put = usePutProjectSLAPolicy();
  const del = useDeleteProjectSLAPolicy();

  const [critical, setCritical] = useState<number>(FALLBACK_DAYS.critical);
  const [high, setHigh] = useState<number>(FALLBACK_DAYS.high);
  const [medium, setMedium] = useState<number>(FALLBACK_DAYS.medium);
  const [low, setLow] = useState<number>(FALLBACK_DAYS.low);
  const [hasOverride, setHasOverride] = useState<boolean>(false);

  // When the loaded policy/settings change, seed the form fields. Project
  // override takes precedence; org defaults fill in otherwise.
  useEffect(() => {
    const days =
      policyQuery.data?.sla_days ??
      settingsQuery.data?.default_finding_sla_days ??
      FALLBACK_DAYS;
    setCritical(days.critical ?? FALLBACK_DAYS.critical);
    setHigh(days.high ?? FALLBACK_DAYS.high);
    setMedium(days.medium ?? FALLBACK_DAYS.medium);
    setLow(days.low ?? FALLBACK_DAYS.low);
    setHasOverride(!!policyQuery.data);
  }, [policyQuery.data, settingsQuery.data]);

  if (policyQuery.isLoading || settingsQuery.isLoading) return <LoadingState rows={3} />;
  if (policyQuery.isError)
    return (
      <ErrorState
        message="Failed to load project SLA policy"
        onRetry={() => policyQuery.refetch()}
      />
    );

  const handleSave = () => {
    put.mutate({
      projectId,
      slaDays: { critical, high, medium, low },
    });
  };

  const handleReset = () => {
    if (!hasOverride) return;
    del.mutate(projectId);
  };

  const inputClass =
    "w-full border rounded-md px-3 py-2 text-sm bg-background focus:outline-none focus:ring-2 focus:ring-primary/40";

  return (
    <div className="space-y-6 max-w-lg">
      <header>
        <h3 className="text-sm font-medium">Project SLA policy</h3>
        <p className="text-xs text-muted-foreground">
          {hasOverride
            ? "This project overrides the org default."
            : "Showing org default — saving will create a project override."}
        </p>
      </header>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="text-xs text-muted-foreground block mb-1" htmlFor="sla-critical">
            Critical (days)
          </label>
          <input
            id="sla-critical"
            type="number"
            min={1}
            value={critical}
            onChange={(e) => setCritical(Number(e.target.value))}
            className={inputClass}
          />
        </div>
        <div>
          <label className="text-xs text-muted-foreground block mb-1" htmlFor="sla-high">
            High (days)
          </label>
          <input
            id="sla-high"
            type="number"
            min={1}
            value={high}
            onChange={(e) => setHigh(Number(e.target.value))}
            className={inputClass}
          />
        </div>
        <div>
          <label className="text-xs text-muted-foreground block mb-1" htmlFor="sla-medium">
            Medium (days)
          </label>
          <input
            id="sla-medium"
            type="number"
            min={1}
            value={medium}
            onChange={(e) => setMedium(Number(e.target.value))}
            className={inputClass}
          />
        </div>
        <div>
          <label className="text-xs text-muted-foreground block mb-1" htmlFor="sla-low">
            Low (days)
          </label>
          <input
            id="sla-low"
            type="number"
            min={1}
            value={low}
            onChange={(e) => setLow(Number(e.target.value))}
            className={inputClass}
          />
        </div>
      </div>

      <div className="flex items-center gap-3">
        <Button onClick={handleSave} disabled={put.isPending}>
          {put.isPending ? "Saving..." : hasOverride ? "Save override" : "Create override"}
        </Button>
        {hasOverride && (
          <Button variant="ghost" onClick={handleReset} disabled={del.isPending}>
            {del.isPending ? "Resetting..." : "Reset to org default"}
          </Button>
        )}
      </div>

      {put.isError && (
        <p className="text-sm text-destructive">Failed to save SLA policy.</p>
      )}
      {put.isSuccess && (
        <p className="text-sm text-green-600">SLA policy saved.</p>
      )}
      {del.isSuccess && (
        <p className="text-sm text-green-600">Project override removed.</p>
      )}
    </div>
  );
}
