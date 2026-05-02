"use client";

import { useMemo, useState } from "react";
import { ChevronDown, Copy, Check, AlertTriangle } from "lucide-react";
import type { HTTPEvidence } from "@/lib/types";

// EvidenceViewer renders the captured HTTP request/response pair as two
// collapsible panels — request first (because it answers "what did we
// send?") then response. Headers are tabular for scanability; bodies are
// rendered in a monospace block with controlled wrapping so long JSON
// stays readable. Sensitive headers/values are marked [REDACTED] by the
// worker before storage; this component does not need to redact.
interface EvidenceViewerProps {
  rawJSON?: string;
  size?: number;
  hash?: string;
}

export function EvidenceViewer({ rawJSON, size, hash }: EvidenceViewerProps) {
  const parsed = useMemo<HTTPEvidence | null>(() => {
    if (!rawJSON) return null;
    try {
      return JSON.parse(rawJSON) as HTTPEvidence;
    } catch {
      return null;
    }
  }, [rawJSON]);

  if (!rawJSON) {
    return (
      <div className="rounded-lg border bg-muted/30 p-4">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <AlertTriangle className="h-4 w-4" />
          No evidence was captured for this finding.
        </div>
      </div>
    );
  }

  if (!parsed) {
    return (
      <div className="rounded-lg border bg-muted/30 p-4">
        <div className="flex items-center gap-2 text-sm text-muted-foreground mb-2">
          <AlertTriangle className="h-4 w-4" />
          Evidence is present but could not be parsed as HTTP exchange JSON.
        </div>
        <pre className="text-[11px] font-mono bg-muted/40 p-2 rounded border overflow-x-auto max-h-64">
          {rawJSON.slice(0, 4096)}
          {rawJSON.length > 4096 ? "\n…" : ""}
        </pre>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <EvidenceMeta parsed={parsed} size={size} hash={hash} />
      <ExchangePanel
        title="Request"
        method={parsed.request.method}
        statusOrUrl={parsed.request.url}
        headers={parsed.request.headers}
        body={parsed.request.body}
      />
      <ExchangePanel
        title="Response"
        method={`HTTP ${parsed.response.status_code}`}
        statusOrUrl={statusLabel(parsed.response.status_code)}
        headers={parsed.response.headers}
        body={parsed.response.body}
        bodySize={parsed.response.body_size}
      />
    </div>
  );
}

function EvidenceMeta({
  parsed,
  size,
  hash,
}: {
  parsed: HTTPEvidence;
  size?: number;
  hash?: string;
}) {
  const items: Array<[string, string]> = [];
  if (parsed.timing_ms !== undefined) items.push(["Timing", `${parsed.timing_ms} ms`]);
  if (parsed.captured_at) items.push(["Captured", new Date(parsed.captured_at).toLocaleString()]);
  if (size !== undefined) items.push(["Size", formatBytes(size)]);
  if (hash) items.push(["SHA-256", hash.slice(0, 16) + "…"]);
  if (items.length === 0) return null;
  return (
    <div className="flex items-center gap-x-4 gap-y-1 flex-wrap text-[11px] text-muted-foreground">
      {items.map(([label, value]) => (
        <span key={label} className="inline-flex items-center gap-1.5">
          <span className="uppercase tracking-wider">{label}</span>
          <span className="font-mono text-foreground">{value}</span>
        </span>
      ))}
    </div>
  );
}

function ExchangePanel({
  title,
  method,
  statusOrUrl,
  headers,
  body,
  bodySize,
}: {
  title: string;
  method: string;
  statusOrUrl: string;
  headers: Record<string, string>;
  body?: string;
  bodySize?: number;
}) {
  const [expanded, setExpanded] = useState(true);
  const headerEntries = Object.entries(headers ?? {}).sort(([a], [b]) => a.localeCompare(b));

  return (
    <div className="rounded-lg border bg-card">
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-muted/40 transition-colors"
      >
        <ChevronDown
          className={`h-4 w-4 shrink-0 text-muted-foreground transition-transform ${expanded ? "" : "-rotate-90"}`}
        />
        <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
          {title}
        </span>
        <span className="text-xs font-mono font-medium text-foreground shrink-0">{method}</span>
        <span className="text-xs font-mono text-muted-foreground truncate flex-1 text-left" title={statusOrUrl}>
          {statusOrUrl}
        </span>
        <span className="text-[10px] text-muted-foreground tabular-nums">
          {headerEntries.length} hdrs{body ? ` · ${formatBytes(bodySize ?? body.length)}` : ""}
        </span>
      </button>
      {expanded && (
        <div className="border-t p-4 space-y-3">
          {headerEntries.length > 0 && <HeaderTable headers={headerEntries} />}
          {body !== undefined && body.length > 0 && <BodyBlock body={body} />}
          {(headerEntries.length === 0 && (!body || body.length === 0)) && (
            <p className="text-xs text-muted-foreground italic">(empty)</p>
          )}
        </div>
      )}
    </div>
  );
}

function HeaderTable({ headers }: { headers: Array<[string, string]> }) {
  return (
    <div className="rounded border overflow-hidden">
      <table className="w-full text-[12px] font-mono">
        <tbody>
          {headers.map(([name, value], i) => {
            const redacted = value === "[REDACTED]";
            return (
              <tr
                key={name}
                className={i % 2 === 0 ? "bg-muted/20" : ""}
              >
                <td className="px-3 py-1.5 text-muted-foreground align-top whitespace-nowrap w-1/3 max-w-[12rem]">
                  {name}
                </td>
                <td className={`px-3 py-1.5 break-all ${redacted ? "italic text-muted-foreground" : "text-foreground"}`}>
                  {value}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function BodyBlock({ body }: { body: string }) {
  const [copied, setCopied] = useState(false);
  const [showFull, setShowFull] = useState(false);
  const TRUNC = 4096;
  const truncated = body.length > TRUNC && !showFull;
  const shown = truncated ? body.slice(0, TRUNC) : body;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(body);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* ignore */
    }
  };

  return (
    <div className="rounded border bg-muted/30">
      <div className="flex items-center justify-between px-3 py-1.5 border-b">
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">
          Body
        </span>
        <button
          type="button"
          onClick={copy}
          className="inline-flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground transition-colors"
        >
          {copied ? <Check className="h-3 w-3 text-severity-low" /> : <Copy className="h-3 w-3" />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="px-3 py-2 text-[11px] font-mono whitespace-pre-wrap break-all overflow-x-auto max-h-96">
        {shown}
        {truncated && (
          <>
            {"\n"}
            <button
              type="button"
              onClick={() => setShowFull(true)}
              className="text-primary hover:underline cursor-pointer"
            >
              Show full body ({formatBytes(body.length)})
            </button>
          </>
        )}
      </pre>
    </div>
  );
}

// ---------- helpers ----------

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function statusLabel(code: number): string {
  if (code >= 200 && code < 300) return `${code} OK-class`;
  if (code >= 300 && code < 400) return `${code} redirect`;
  if (code >= 400 && code < 500) return `${code} client error`;
  if (code >= 500) return `${code} server error`;
  return String(code);
}
