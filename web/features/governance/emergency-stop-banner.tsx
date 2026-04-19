"use client";

import { AlertTriangle } from "lucide-react";
import { useEmergencyStops } from "./hooks";

export function EmergencyStopBanner() {
  const { data } = useEmergencyStops();
  const stops = data?.stops ?? [];

  if (stops.length === 0) return null;

  return (
    <div className="bg-destructive/15 border border-destructive/30 rounded-lg px-4 py-3 mb-4">
      <div className="flex items-start gap-3">
        <AlertTriangle className="h-5 w-5 text-destructive shrink-0 mt-0.5" />
        <div className="space-y-1">
          <p className="text-sm font-medium text-destructive">
            Emergency Stop Active
          </p>
          {stops.map((stop) => (
            <p key={stop.id} className="text-xs text-destructive/80">
              <span className="font-medium capitalize">{stop.scope}</span>
              {stop.scope_id && <span> ({stop.scope_id})</span>}
              {" — "}
              {stop.reason}
            </p>
          ))}
        </div>
      </div>
    </div>
  );
}
