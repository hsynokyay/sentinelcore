"use client";

import Link from "next/link";
import { AlertTriangle, SearchX } from "lucide-react";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/data/empty-state";
import type { RiskStatus } from "@/lib/types";

type StatusFilter = RiskStatus | "all";

const FILTER_LABELS: Record<StatusFilter, string> = {
  active: "active",
  user_resolved: "resolved",
  muted: "muted",
  auto_resolved: "auto-resolved",
  all: "all",
};

interface RisksEmptyStateProps {
  /** Total risk count across ALL status filters for the current project.
   *  When this is 0, the project has never produced a risk → "no risks
   *  yet" empty state. When > 0 but the table is empty, the current
   *  filter excludes everything → "no matching risks" empty state. */
  totalRisks: number;
  /** The active status filter, used to label the "no matching" state
   *  ("No active risks" vs "No resolved risks"). */
  currentFilter: StatusFilter;
  /** Reset the filter to "all" — used as the CTA on the "no matching"
   *  state so the user can broaden their view with one click. */
  onClearFilter: () => void;
}

/**
 * RisksEmptyState — the canonical empty-state picker for the /risks
 * page. Distinguishes between two scenarios:
 *
 *  1. **No risks in project at all** (totalRisks === 0):
 *     The project has never been scanned, or scanning hasn't produced
 *     correlated risks yet. The CTA sends the user to /scans to
 *     trigger their first scan.
 *
 *  2. **No risks match the current filter** (totalRisks > 0):
 *     Risks exist but the status filter ("Active", "Resolved", etc.)
 *     excludes all of them. The CTA resets the filter to "All".
 *
 * Both states use the upgraded EmptyState template with a domain icon,
 * a description, an optional suggestion, and a clear CTA. The user
 * never stares at "No data found" with no guidance.
 */
export function RisksEmptyState({
  totalRisks,
  currentFilter,
  onClearFilter,
}: RisksEmptyStateProps) {
  if (totalRisks === 0) {
    return (
      <EmptyState
        icon={<AlertTriangle className="h-12 w-12" />}
        title="No risks yet"
        description="Risks appear after a scan correlates findings across SAST, DAST, and attack surface data."
        suggestion="Run your first scan, then check back here."
        action={
          <Link href="/scans">
            <Button variant="default" size="sm">
              Go to Scans
            </Button>
          </Link>
        }
      />
    );
  }

  // No risks match the current filter.
  const filterLabel = FILTER_LABELS[currentFilter] ?? currentFilter;

  return (
    <EmptyState
      icon={<SearchX className="h-12 w-12" />}
      title={`No ${filterLabel} risks`}
      description={
        currentFilter === "all"
          ? "No risks matched your search criteria."
          : `This project has risks, but none are in the "${filterLabel}" state right now.`
      }
      action={
        currentFilter !== "all" ? (
          <Button variant="outline" size="sm" onClick={onClearFilter}>
            Show all risks
          </Button>
        ) : undefined
      }
    />
  );
}
