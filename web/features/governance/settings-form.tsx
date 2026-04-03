"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { useSettings, useUpdateSettings } from "./hooks";
import { LoadingState } from "@/components/data/loading-state";
import { ErrorState } from "@/components/data/error-state";

export function SettingsForm() {
  const { data: settings, isLoading, isError, refetch } = useSettings();
  const update = useUpdateSettings();

  const [requireRiskAcceptance, setRequireRiskAcceptance] = useState(false);
  const [requireFalsePositive, setRequireFalsePositive] = useState(false);
  const [slaCritical, setSlaCritical] = useState(1);
  const [slaHigh, setSlaHigh] = useState(3);
  const [slaMedium, setSlaMedium] = useState(7);
  const [slaLow, setSlaLow] = useState(30);

  useEffect(() => {
    if (settings) {
      setRequireRiskAcceptance(settings.require_approval_for_risk_acceptance);
      setRequireFalsePositive(settings.require_approval_for_false_positive);
      const sla = settings.default_finding_sla_days;
      if (sla.critical !== undefined) setSlaCritical(sla.critical);
      if (sla.high !== undefined) setSlaHigh(sla.high);
      if (sla.medium !== undefined) setSlaMedium(sla.medium);
      if (sla.low !== undefined) setSlaLow(sla.low);
    }
  }, [settings]);

  if (isLoading) return <LoadingState rows={4} />;
  if (isError) return <ErrorState message="Failed to load settings" onRetry={() => refetch()} />;

  const handleSave = () => {
    update.mutate({
      require_approval_for_risk_acceptance: requireRiskAcceptance,
      require_approval_for_false_positive: requireFalsePositive,
      default_finding_sla_days: {
        critical: slaCritical,
        high: slaHigh,
        medium: slaMedium,
        low: slaLow,
      },
    });
  };

  return (
    <div className="space-y-8 max-w-lg">
      {/* Approval Requirements */}
      <section>
        <h3 className="text-sm font-medium mb-4">Approval Requirements</h3>
        <div className="space-y-3">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={requireRiskAcceptance}
              onChange={(e) => setRequireRiskAcceptance(e.target.checked)}
              className="rounded border-gray-300"
            />
            <span className="text-sm">Require approval for risk acceptance</span>
          </label>
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={requireFalsePositive}
              onChange={(e) => setRequireFalsePositive(e.target.checked)}
              className="rounded border-gray-300"
            />
            <span className="text-sm">Require approval for false positive markings</span>
          </label>
        </div>
      </section>

      {/* SLA Configuration */}
      <section>
        <h3 className="text-sm font-medium mb-4">Finding SLA (days)</h3>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Critical</label>
            <input
              type="number"
              min={1}
              value={slaCritical}
              onChange={(e) => setSlaCritical(Number(e.target.value))}
              className="w-full border rounded-md px-3 py-2 text-sm bg-background"
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">High</label>
            <input
              type="number"
              min={1}
              value={slaHigh}
              onChange={(e) => setSlaHigh(Number(e.target.value))}
              className="w-full border rounded-md px-3 py-2 text-sm bg-background"
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Medium</label>
            <input
              type="number"
              min={1}
              value={slaMedium}
              onChange={(e) => setSlaMedium(Number(e.target.value))}
              className="w-full border rounded-md px-3 py-2 text-sm bg-background"
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Low</label>
            <input
              type="number"
              min={1}
              value={slaLow}
              onChange={(e) => setSlaLow(Number(e.target.value))}
              className="w-full border rounded-md px-3 py-2 text-sm bg-background"
            />
          </div>
        </div>
      </section>

      <Button onClick={handleSave} disabled={update.isPending}>
        {update.isPending ? "Saving..." : "Save Settings"}
      </Button>
      {update.isError && (
        <p className="text-sm text-destructive">Failed to save settings.</p>
      )}
      {update.isSuccess && (
        <p className="text-sm text-green-600">Settings saved successfully.</p>
      )}
    </div>
  );
}
