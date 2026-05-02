"use client";

import { useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  ShieldCheck,
  AlertTriangle,
  Wrench,
  CheckCircle2,
  ExternalLink,
  Copy,
  Check,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { RemediationBlock } from "@/lib/types";

interface RemediationPanelProps {
  remediation: RemediationBlock;
}

/**
 * RemediationPanel renders structured developer guidance for a finding.
 * Designed to feel like Fortify/Checkmarx remediation guidance but cleaner
 * and more product-native. Only renders when remediation data is present.
 */
export function RemediationPanel({ remediation }: RemediationPanelProps) {
  return (
    <section className="space-y-4">
      <h3 className="text-sm font-medium text-muted-foreground flex items-center gap-2">
        <Wrench className="h-4 w-4" />
        Remediation Guidance
      </h3>

      <div className="rounded-lg border bg-card divide-y">
        {/* What happened */}
        <CollapsibleSection
          title="What happened"
          icon={<AlertTriangle className="h-3.5 w-3.5 text-amber-600" />}
          defaultOpen
        >
          <p className="text-sm leading-relaxed">{remediation.summary}</p>
        </CollapsibleSection>

        {/* Why it matters */}
        <CollapsibleSection
          title="Why it matters"
          icon={<ShieldCheck className="h-3.5 w-3.5 text-red-600" />}
          defaultOpen
        >
          <p className="text-sm leading-relaxed">{remediation.why_it_matters}</p>
        </CollapsibleSection>

        {/* How to fix */}
        <CollapsibleSection
          title="How to fix"
          icon={<Wrench className="h-3.5 w-3.5 text-emerald-600" />}
          defaultOpen
        >
          <div className="text-sm leading-relaxed whitespace-pre-line">
            {remediation.how_to_fix}
          </div>
        </CollapsibleSection>

        {/* Unsafe example */}
        <CollapsibleSection title="Unsafe example" badge="avoid" defaultOpen={false}>
          <CodeBlock code={remediation.unsafe_example} variant="unsafe" />
        </CollapsibleSection>

        {/* Safe example */}
        <CollapsibleSection title="Safe example" badge="recommended" defaultOpen>
          <CodeBlock code={remediation.safe_example} variant="safe" />
        </CollapsibleSection>

        {/* Developer notes */}
        {remediation.developer_notes && (
          <CollapsibleSection title="Developer notes" defaultOpen={false}>
            <p className="text-sm leading-relaxed">{remediation.developer_notes}</p>
          </CollapsibleSection>
        )}

        {/* Verification checklist */}
        <CollapsibleSection
          title="Verification checklist"
          icon={<CheckCircle2 className="h-3.5 w-3.5 text-emerald-600" />}
          defaultOpen
        >
          <ul className="space-y-2">
            {remediation.verification_checklist.map((item, i) => (
              <li key={i} className="flex items-start gap-2 text-sm">
                <span className="mt-0.5 h-4 w-4 rounded border flex items-center justify-center text-muted-foreground text-[10px] shrink-0">
                  {i + 1}
                </span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </CollapsibleSection>

        {/* References */}
        {remediation.references.length > 0 && (
          <div className="px-4 py-3">
            <h4 className="text-xs font-medium text-muted-foreground mb-2">
              References
            </h4>
            <ul className="space-y-1">
              {remediation.references.map((ref, i) => (
                <li key={i}>
                  <a
                    href={ref.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-primary hover:underline underline-offset-4 inline-flex items-center gap-1"
                  >
                    {ref.title}
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </section>
  );
}

// --- Sub-components ---

interface CollapsibleSectionProps {
  title: string;
  icon?: React.ReactNode;
  badge?: "avoid" | "recommended";
  defaultOpen?: boolean;
  children: React.ReactNode;
}

function CollapsibleSection({
  title,
  icon,
  badge,
  defaultOpen = false,
  children,
}: CollapsibleSectionProps) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-2 px-4 py-3 text-sm font-medium text-foreground hover:bg-muted/50 transition-colors select-none"
      >
        {open ? (
          <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
        )}
        {icon}
        {title}
        {badge === "avoid" && (
          <Badge variant="outline" className="ml-1 text-[10px] bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-300">
            avoid
          </Badge>
        )}
        {badge === "recommended" && (
          <Badge variant="outline" className="ml-1 text-[10px] bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300">
            recommended
          </Badge>
        )}
      </button>
      {open && <div className="px-4 pb-4">{children}</div>}
    </div>
  );
}

interface CodeBlockProps {
  code: string;
  variant: "safe" | "unsafe";
}

function CodeBlock({ code, variant }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const copyToClipboard = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const borderColor =
    variant === "safe"
      ? "border-emerald-200 dark:border-emerald-800"
      : "border-red-200 dark:border-red-800";
  const bgColor =
    variant === "safe"
      ? "bg-emerald-50/50 dark:bg-emerald-950/20"
      : "bg-red-50/50 dark:bg-red-950/20";

  return (
    <div className={`relative rounded-md border ${borderColor} ${bgColor}`}>
      <button
        type="button"
        onClick={copyToClipboard}
        className="absolute top-2 right-2 p-1 rounded hover:bg-muted/80 text-muted-foreground"
        title="Copy to clipboard"
      >
        {copied ? (
          <Check className="h-3.5 w-3.5 text-emerald-600" />
        ) : (
          <Copy className="h-3.5 w-3.5" />
        )}
      </button>
      <pre className="px-4 py-3 text-xs font-mono overflow-x-auto leading-relaxed">
        {code}
      </pre>
    </div>
  );
}
