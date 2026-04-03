"use client";

import { useState } from "react";
import { AlertTriangle, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { useEmergencyStops, useLiftEmergencyStop } from "./hooks";
import { EmergencyStopDialog } from "./emergency-stop-dialog";

export function EmergencyStopSection() {
  const [dialogOpen, setDialogOpen] = useState(false);
  const { data, isLoading } = useEmergencyStops();
  const liftStop = useLiftEmergencyStop();

  const stops = data?.stops ?? [];

  const handleLift = (stopId: string) => {
    liftStop.mutate(stopId, {
      onSuccess: () => {
        toast.success("Emergency stop lifted");
      },
      onError: (error) => {
        toast.error("Failed to lift emergency stop", {
          description: error instanceof Error ? error.message : "Unknown error",
        });
      },
    });
  };

  return (
    <section className="mt-10 max-w-lg">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-medium flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-destructive" />
          Emergency Stop
        </h3>
        <Button variant="destructive" size="sm" onClick={() => setDialogOpen(true)}>
          Activate Emergency Stop
        </Button>
      </div>

      {isLoading && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground py-4">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading...
        </div>
      )}

      {!isLoading && stops.length === 0 && (
        <p className="text-sm text-muted-foreground py-4">
          No active emergency stops.
        </p>
      )}

      {stops.length > 0 && (
        <div className="space-y-3">
          {stops.map((stop) => (
            <div
              key={stop.id}
              className="rounded-lg border border-destructive/30 bg-destructive/5 p-4"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium capitalize">{stop.scope}</span>
                    {stop.scope_id && (
                      <span className="text-xs text-muted-foreground font-mono truncate">
                        {stop.scope_id}
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground">{stop.reason}</p>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    <span>By: {stop.activated_by}</span>
                    <span>At: {new Date(stop.activated_at).toLocaleString()}</span>
                  </div>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleLift(stop.id)}
                  disabled={liftStop.isPending}
                >
                  {liftStop.isPending ? (
                    <Loader2 className="h-3 w-3 animate-spin mr-1" />
                  ) : null}
                  Lift
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      <EmergencyStopDialog open={dialogOpen} onOpenChange={setDialogOpen} />
    </section>
  );
}
