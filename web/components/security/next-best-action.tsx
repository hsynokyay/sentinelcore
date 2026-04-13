"use client";

import Link from "next/link";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { SeverityStrip } from "@/components/security/severity-strip";
import {
  intensityBorderClass,
  intensityHaloStyle,
  type IntensityLevel,
} from "@/lib/security/intensity";
import type { RiskSeverity } from "@/lib/types";

/**
 * One call-to-action shape, used for both the primary and the secondary
 * button on the panel. A CTA can be either an internal navigation
 * (`href`) or a JS handler (`onClick`) — internally we render a Next.js
 * `<Link>` for the former and a plain button for the latter.
 */
export interface NextBestActionCta {
  label: string;
  href?: string;
  onClick?: () => void;
  /** Override the visual treatment. Defaults to `default` for primary,
   *  `outline` for secondary. */
  variant?: "default" | "outline" | "ghost";
}

export interface NextBestActionProps {
  /** Severity that drives the left rail colour. Same vocabulary as the
   *  table row strip — risk detail and risk row share a single visual
   *  anchor for "this is critical". */
  severity: RiskSeverity;
  /** Intensity level (0..4) computed by the consumer. Drives the panel's
   *  border weight and (at level 4) the critical halo. */
  intensity: IntensityLevel;
  /** Action title — already humanised by the consumer. Use the imperative
   *  ("Patch this week", "Monitor only"), not the descriptive. */
  title: string;
  /** Brief reasons explaining why this action is recommended. Each entry
   *  should be a complete short phrase ("Critical severity",
   *  "Confirmed at runtime"). 2-4 reasons reads best — fewer feels thin,
   *  more starts to compete with the title. */
  reasons: string[];
  /** Primary call-to-action. Almost always a navigation that starts the
   *  investigation flow. */
  primaryAction?: NextBestActionCta;
  /** Optional secondary CTA (e.g. "Mark as risk accepted"). */
  secondaryAction?: NextBestActionCta;
  className?: string;
}

/**
 * Render a single CTA as either a Link-wrapped Button (when `href` is
 * present) or a plain Button (when `onClick` is). Defaults the visual
 * treatment to the supplied `defaultVariant`.
 */
function ActionButton({
  cta,
  defaultVariant,
}: {
  cta: NextBestActionCta;
  defaultVariant: "default" | "outline";
}) {
  const variant = cta.variant ?? defaultVariant;
  const button = (
    <Button variant={variant} onClick={cta.onClick} size="sm">
      {cta.label}
    </Button>
  );
  if (cta.href) {
    return (
      <Link href={cta.href} className="inline-block">
        {button}
      </Link>
    );
  }
  return button;
}

/**
 * NextBestAction — the "what should I do RIGHT NOW?" panel.
 *
 * The panel is the explainability surface's actionable counterpart: the
 * EvidencePanel answers *why* a risk was ranked the way it was, this one
 * answers *what to do about it*. Same controlled-intensity philosophy as
 * the rest of the security primitives — calm by default, escalation is
 * earned through real signals (severity + runtime + exposure), and
 * escalation manifests as tighter borders + (at level 4) a halo, never
 * as a chrome-decoration spike.
 *
 * Layout: a left severity rail (matches the risks-table row vocabulary),
 * an eyebrow "NEXT BEST ACTION" label, the focal action title, an
 * inline list of reasons in muted text, and one or two CTAs at the
 * bottom. The whole thing is a single horizontal flex with the rail
 * anchored to its left edge — the same SeverityStrip primitive used in
 * the table.
 *
 * The panel is severity-coloured but lifecycle-agnostic — it's always
 * rendered for active risks, never rendered for resolved/muted ones (the
 * caller is expected to handle that conditional).
 */
export function NextBestAction({
  severity,
  intensity,
  title,
  reasons,
  primaryAction,
  secondaryAction,
  className,
}: NextBestActionProps) {
  // Border weight comes from the intensity helper so a future tweak to
  // "what counts as urgent" propagates without touching this component.
  const borderClass = intensityBorderClass(intensity);
  const haloStyle = intensityHaloStyle(intensity, severity);

  return (
    <section
      className={cn(
        "relative overflow-hidden rounded-lg border bg-card",
        borderClass,
        className,
      )}
      style={haloStyle}
      aria-label="Next best action"
    >
      {/* Left severity rail — same primitive as the risks-table row. The
          parent section is `position: relative` so the absolutely-
          positioned strip uses it as its containing block and naturally
          fills the section's full height. */}
      <SeverityStrip severity={severity} thickness={4} />

      {/* Content padding has to reserve space for the rail (4px wide) plus
          a small visual gap, since the rail is out of normal flow. */}
      <div className="p-4 pl-5">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
          Next best action
        </p>
        <h2 className="mt-1 text-lg font-semibold leading-tight text-foreground">
          {title}
        </h2>

        {reasons.length > 0 && (
          <ul className="mt-3 flex flex-wrap items-center gap-x-1 text-xs text-muted-foreground">
            {reasons.map((reason, idx) => (
              <li key={`${idx}-${reason}`} className="flex items-center gap-1">
                {idx > 0 && <span aria-hidden="true">·</span>}
                <span>{reason}</span>
              </li>
            ))}
          </ul>
        )}

        {(primaryAction || secondaryAction) && (
          <div className="mt-4 flex items-center gap-2">
            {primaryAction && (
              <ActionButton cta={primaryAction} defaultVariant="default" />
            )}
            {secondaryAction && (
              <ActionButton cta={secondaryAction} defaultVariant="outline" />
            )}
          </div>
        )}
      </div>
    </section>
  );
}
