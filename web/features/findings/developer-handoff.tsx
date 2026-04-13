"use client";

import { useState } from "react";
import { ClipboardCopy, Check, ExternalLink } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { formatTicketHandoff } from "./ticket-formatter";
import type { Finding } from "@/lib/types";

interface DeveloperHandoffProps {
  finding: Finding;
}

/**
 * DeveloperHandoff renders a compact summary block optimized for copying
 * into external ticketing systems (Jira, GitHub Issues, Azure DevOps, etc.).
 *
 * Only renders when the finding has enough context to be useful — at
 * minimum a title and either a file path or remediation data.
 */
export function DeveloperHandoff({ finding }: DeveloperHandoffProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    const text = formatTicketHandoff(finding);
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      toast.success("Copied to clipboard", {
        description: "Paste into your ticketing system",
      });
      setTimeout(() => setCopied(false), 2500);
    });
  };

  const rem = finding.remediation;
  const location = finding.file_path
    ? `${finding.file_path}${finding.line_number ? `:${finding.line_number}` : ""}`
    : finding.url || null;

  return (
    <section>
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2">
          <ExternalLink className="h-4 w-4" />
          Developer Handoff
        </h3>
        <Button
          variant="outline"
          size="sm"
          onClick={handleCopy}
          className="gap-1.5"
        >
          {copied ? (
            <Check className="h-3.5 w-3.5 text-emerald-600" />
          ) : (
            <ClipboardCopy className="h-3.5 w-3.5" />
          )}
          {copied ? "Copied" : "Copy for Ticket"}
        </Button>
      </div>

      <div className="rounded-lg border bg-muted/30 px-4 py-3 space-y-2 text-sm">
        {/* Title + severity */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-medium">{finding.title}</span>
          <Badge
            variant="outline"
            className="text-[10px]"
          >
            {finding.severity}
          </Badge>
          {finding.rule_id && (
            <span className="text-xs text-muted-foreground font-mono">
              {finding.rule_id}
            </span>
          )}
        </div>

        {/* Location */}
        {location && (
          <div className="font-mono text-xs text-muted-foreground truncate">
            {location}
          </div>
        )}

        {/* Summary */}
        {rem && (
          <p className="text-muted-foreground leading-relaxed">
            {rem.summary}
          </p>
        )}

        {/* Top fix steps */}
        {rem && rem.how_to_fix && (
          <div>
            <span className="text-xs font-medium text-muted-foreground">
              Fix:
            </span>
            <ul className="mt-0.5 space-y-0.5">
              {extractSteps(rem.how_to_fix, 3).map((step, i) => (
                <li key={i} className="text-xs text-muted-foreground flex items-start gap-1.5">
                  <span className="text-[10px] mt-0.5 shrink-0">→</span>
                  {step}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Top checklist items */}
        {rem && rem.verification_checklist.length > 0 && (
          <div>
            <span className="text-xs font-medium text-muted-foreground">
              Verify:
            </span>
            <ul className="mt-0.5 space-y-0.5">
              {rem.verification_checklist.slice(0, 3).map((item, i) => (
                <li key={i} className="text-xs text-muted-foreground flex items-start gap-1.5">
                  <span className="text-[10px] mt-0.5 shrink-0">☐</span>
                  {item}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </section>
  );
}

/**
 * Extracts the first N actionable steps from how_to_fix text.
 * Same logic as ticket-formatter but inline for the preview.
 */
function extractSteps(howToFix: string, max: number): string[] {
  const numbered = howToFix.match(/^\d+\.\s+.+$/gm);
  if (numbered && numbered.length > 0) {
    return numbered.slice(0, max).map((s) => s.replace(/^\d+\.\s+/, "").trim());
  }
  const bullets = howToFix.match(/^[-*]\s+.+$/gm);
  if (bullets && bullets.length > 0) {
    return bullets.slice(0, max).map((s) => s.replace(/^[-*]\s+/, "").trim());
  }
  return howToFix
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 10 && !l.startsWith("**"))
    .slice(0, max);
}
