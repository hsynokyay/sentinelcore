"use client";

import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useSSOLoginHistory } from "./hooks";
import type { SSOLoginEvent, SSOLoginOutcome } from "./types";

interface HistoryPanelProps {
  providerId: string;
}

/**
 * Renders the last 50 SSO login attempts for a provider. Click a row to
 * reveal the redacted claim payload (64-char-truncated query string
 * values, with secret-looking keys dropped at write time in the backend).
 *
 * Auto-refreshes every 10 seconds so an admin running a live test
 * session sees new rows without manually reloading.
 */
export function HistoryPanel({ providerId }: HistoryPanelProps) {
  const { data: events, isLoading, error } = useSSOLoginHistory(providerId);
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});

  return (
    <div className="border rounded-md p-4 space-y-4">
      <div>
        <h3 className="text-base font-semibold">Recent login attempts</h3>
        <p className="text-xs text-muted-foreground">
          Last 50 callback events, newest first. Auto-refreshes every 10s.
        </p>
      </div>

      {isLoading && (
        <p className="text-sm text-muted-foreground">Loading…</p>
      )}
      {error && (
        <div className="p-2 text-xs text-destructive bg-destructive/10 rounded">
          {(error as Error).message}
        </div>
      )}
      {!isLoading && events && events.length === 0 && (
        <p className="text-xs text-muted-foreground">
          No events yet. Trigger a test login via{" "}
          <code>/api/v1/auth/sso/&lt;org&gt;/&lt;provider&gt;/start</code> to
          populate this log.
        </p>
      )}
      {!isLoading && events && events.length > 0 && (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-6" />
              <TableHead className="w-40">When</TableHead>
              <TableHead className="w-28">Outcome</TableHead>
              <TableHead>Error</TableHead>
              <TableHead>Email</TableHead>
              <TableHead>Role granted</TableHead>
              <TableHead className="w-28">IP</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {events.map((e) => (
              <EventRow
                key={e.id}
                event={e}
                expanded={!!expanded[e.id]}
                toggle={() =>
                  setExpanded((p) => ({ ...p, [e.id]: !p[e.id] }))
                }
              />
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}

function EventRow(props: {
  event: SSOLoginEvent;
  expanded: boolean;
  toggle: () => void;
}) {
  const { event, expanded, toggle } = props;
  const hasClaims =
    !!event.claims_redacted &&
    Object.keys(event.claims_redacted).length > 0;

  return (
    <>
      <TableRow
        className="cursor-pointer"
        onClick={hasClaims ? toggle : undefined}
      >
        <TableCell>
          {hasClaims ? (
            expanded ? (
              <ChevronDown className="h-3 w-3" />
            ) : (
              <ChevronRight className="h-3 w-3" />
            )
          ) : null}
        </TableCell>
        <TableCell className="font-mono text-xs">
          {formatWhen(event.occurred_at)}
        </TableCell>
        <TableCell>{outcomeBadge(event.outcome)}</TableCell>
        <TableCell className="font-mono text-xs text-muted-foreground">
          {event.error_code || "—"}
        </TableCell>
        <TableCell className="text-xs">{event.email || "—"}</TableCell>
        <TableCell className="font-mono text-xs">
          {event.role_granted || "—"}
        </TableCell>
        <TableCell className="font-mono text-xs">
          {event.ip_address || "—"}
        </TableCell>
      </TableRow>
      {expanded && hasClaims && (
        <TableRow>
          <TableCell />
          <TableCell colSpan={6} className="bg-muted/30">
            <pre className="text-xs overflow-x-auto">
              {JSON.stringify(event.claims_redacted, null, 2)}
            </pre>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

function outcomeBadge(o: SSOLoginOutcome) {
  switch (o) {
    case "success":
      return <Badge variant="default">success</Badge>;
    case "callback_error":
      return <Badge variant="destructive">callback</Badge>;
    case "claim_error":
      return <Badge variant="destructive">claim</Badge>;
    case "user_error":
      return <Badge variant="secondary">user</Badge>;
  }
}

function formatWhen(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return iso;
  }
}
