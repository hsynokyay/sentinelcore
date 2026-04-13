"use client";

import { ShieldCheck, Clock, ShieldAlert, ShieldOff, Shield } from "lucide-react";
import { cn } from "@/lib/utils";
import { PulseDot, type PulseDotTone } from "./pulse-dot";

/**
 * The five canonical trust states for any credentialed entity in
 * SentinelCore — scan targets, source artifacts, auth profiles, etc.
 *
 * - `verified` — ownership / integrity proven and current
 * - `pending`  — credential or proof not yet established
 * - `expired`  — was once verified, now stale (e.g. cert expired)
 * - `revoked`  — explicitly revoked or marked unsafe
 * - `unknown`  — no information available (rare; usually a bug)
 */
export type TrustState = "verified" | "pending" | "expired" | "revoked" | "unknown";

export type TrustChipSize = "sm" | "md";

export interface TrustChipProps {
  /** The trust state — drives icon, colour, and pulse semantics. */
  state: TrustState;
  /** Display label. Falls back to a humanised state string when omitted. */
  label?: string;
  /** Override the default state icon. Pass `null` to hide the icon entirely. */
  icon?: React.ReactNode | null;
  /** Add a small PulseDot inside the chip — used when this trust state is
   *  *actively signalling* (e.g. an active emergency stop) vs just being
   *  the current attribute of an entity. Defaults to false. */
  pulsing?: boolean;
  /** Size preset. sm (default) is a dense table-cell chip; md is a
   *  more breathing-room version for cards or detail pages. */
  size?: TrustChipSize;
  className?: string;
}

interface StateConfig {
  /** Default Lucide icon. Consumers can override via `icon` prop. */
  defaultIcon: React.ComponentType<{ className?: string }>;
  /** Tailwind classes for chip background + border + text colour.
   *  Backgrounds use color-mix on the existing pulse-* tokens, mirroring
   *  the DeltaChip pattern from Task 7 — no new palette. */
  toneClass: string;
  /** PulseDot tone to use when `pulsing` is true. */
  pulseTone: PulseDotTone;
  /** Default human-readable label for the state, used when the consumer
   *  doesn't pass an explicit label. */
  defaultLabel: string;
}

const stateConfig: Record<TrustState, StateConfig> = {
  verified: {
    defaultIcon: ShieldCheck,
    toneClass:
      "bg-[color-mix(in_oklch,var(--pulse-ok)_15%,transparent)] border-[color-mix(in_oklch,var(--pulse-ok)_30%,transparent)] text-[var(--pulse-ok)]",
    pulseTone: "ok",
    defaultLabel: "Verified",
  },
  pending: {
    defaultIcon: Clock,
    toneClass:
      "bg-[color-mix(in_oklch,var(--pulse-warn)_15%,transparent)] border-[color-mix(in_oklch,var(--pulse-warn)_30%,transparent)] text-[var(--pulse-warn)]",
    pulseTone: "warn",
    defaultLabel: "Pending",
  },
  expired: {
    defaultIcon: ShieldAlert,
    toneClass:
      "bg-[color-mix(in_oklch,var(--pulse-warn)_15%,transparent)] border-[color-mix(in_oklch,var(--pulse-warn)_30%,transparent)] text-[var(--pulse-warn)]",
    pulseTone: "warn",
    defaultLabel: "Expired",
  },
  revoked: {
    defaultIcon: ShieldOff,
    toneClass:
      "bg-[color-mix(in_oklch,var(--pulse-err)_15%,transparent)] border-[color-mix(in_oklch,var(--pulse-err)_30%,transparent)] text-[var(--pulse-err)]",
    pulseTone: "err",
    defaultLabel: "Revoked",
  },
  unknown: {
    defaultIcon: Shield,
    toneClass: "bg-muted border-border text-muted-foreground",
    pulseTone: "warn",
    defaultLabel: "Unknown",
  },
};

const sizeClass: Record<TrustChipSize, string> = {
  sm: "h-5 px-1.5 gap-1 text-[10px] [&_svg]:size-3",
  md: "h-6 px-2 gap-1.5 text-xs [&_svg]:size-3.5",
};

/**
 * TrustChip — a small bordered chip that communicates the trust state
 * of a credentialed entity. The chip pairs a state-specific Lucide
 * icon with a label and (optionally) a live PulseDot.
 *
 * Why this exists: SentinelCore has several places that show "is this
 * thing trustworthy?" — scan targets, source artifacts, auth profiles,
 * cert pins, allow-listed domains. Before this primitive, every
 * consumer rolled its own ad-hoc badge with hand-picked Tailwind colours
 * (`bg-emerald-100` / `bg-amber-100`). The chip unifies that vocabulary
 * on the existing pulse-* tokens so the trust band is consistent
 * across the entire app — same green for "verified" everywhere, same
 * yellow for "pending", same red for "revoked".
 *
 * Backgrounds and borders use `color-mix(in oklch, ...)` on the same
 * tokens that power PulseDot. This is the same pattern Task 7's
 * DeltaChip uses — no new palette, derived from the design system.
 */
export function TrustChip({
  state,
  label,
  icon,
  pulsing = false,
  size = "sm",
  className,
}: TrustChipProps) {
  const config = stateConfig[state];
  const Icon = config.defaultIcon;
  const displayLabel = label ?? config.defaultLabel;
  const showIcon = icon !== null;

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border font-medium uppercase tracking-wide whitespace-nowrap",
        sizeClass[size],
        config.toneClass,
        className,
      )}
      data-trust-state={state}
    >
      {pulsing && <PulseDot tone={config.pulseTone} size="xs" />}
      {showIcon && (icon ?? <Icon aria-hidden="true" />)}
      <span>{displayLabel}</span>
    </span>
  );
}
