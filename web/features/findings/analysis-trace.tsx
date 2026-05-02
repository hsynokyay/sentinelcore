"use client";

import { useState } from "react";
import { ChevronDown, ChevronRight, ArrowDown, CircleDot, Waypoints, Target } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { TaintPathStep } from "@/lib/types";

const kindConfig: Record<
  string,
  { label: string; color: string; icon: typeof CircleDot }
> = {
  source: {
    label: "Source",
    color: "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300",
    icon: CircleDot,
  },
  propagation: {
    label: "Flow",
    color: "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300",
    icon: Waypoints,
  },
  sink: {
    label: "Sink",
    color: "bg-violet-100 text-violet-800 dark:bg-violet-900/40 dark:text-violet-300",
    icon: Target,
  },
};

interface AnalysisTraceProps {
  steps: TaintPathStep[];
}

/**
 * AnalysisTrace renders the SAST evidence chain (taint path) for a finding.
 * It's a collapsible section that shows each step in the source → flow →
 * sink trace, so a reviewer can understand exactly how the finding was
 * derived without guessing.
 *
 * Only renders when `steps.length > 0`; the caller is responsible for
 * checking this before mounting.
 */
export function AnalysisTrace({ steps }: AnalysisTraceProps) {
  const [expanded, setExpanded] = useState(true);

  if (steps.length === 0) return null;

  return (
    <section>
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors mb-2 select-none"
      >
        {expanded ? (
          <ChevronDown className="h-4 w-4" />
        ) : (
          <ChevronRight className="h-4 w-4" />
        )}
        Analysis Trace
        <span className="text-xs font-normal">
          ({steps.length} step{steps.length !== 1 ? "s" : ""})
        </span>
      </button>

      {expanded && (
        <div className="rounded-md border bg-card">
          {steps.map((step, i) => {
            const cfg = kindConfig[step.step_kind] ?? kindConfig.propagation;
            const Icon = cfg.icon;
            const isLast = i === steps.length - 1;

            return (
              <div key={step.step_index}>
                <div className="flex items-start gap-3 px-4 py-3">
                  {/* Step connector */}
                  <div className="flex flex-col items-center pt-0.5">
                    <div className="rounded-full p-1 border bg-background">
                      <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                    </div>
                    {!isLast && (
                      <div className="flex-1 flex items-center justify-center py-1">
                        <ArrowDown className="h-3 w-3 text-muted-foreground/50" />
                      </div>
                    )}
                  </div>

                  {/* Step content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge
                        variant="outline"
                        className={`text-[10px] px-1.5 py-0 ${cfg.color}`}
                      >
                        {cfg.label}
                      </Badge>
                      <span className="text-xs text-muted-foreground">
                        Step {step.step_index + 1}
                      </span>
                    </div>

                    <p className="text-sm">{step.detail}</p>

                    <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                      <span className="font-mono truncate max-w-[300px]">
                        {step.file_path}
                      </span>
                      <span>
                        line {step.line_start}
                        {step.line_end && step.line_end !== step.line_start
                          ? `–${step.line_end}`
                          : ""}
                      </span>
                      {step.function_fqn && (
                        <span className="font-mono truncate max-w-[260px]">
                          {step.function_fqn}
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Divider between steps */}
                {!isLast && <div className="border-b mx-4" />}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
