# System Status Bar — Design Spec

**Date:** 2026-04-13
**Status:** Draft
**Scope:** Persistent bottom-bar trust strip in the SentinelCore app shell

## Problem

The dashboard's KPI tiles and chart cards show *risk* state but not *platform* state. An operator looking at the UI cannot tell whether scans are healthy, data is fresh, or backend systems are operational — they only know when an emergency stop is active (the red ESTOP dot in the header). The trust layer needs to be persistent and visible, not just reactive to emergencies.

## Decision

Add a thin, always-visible status bar pinned to the bottom of the AppShell content column. The bar composes the existing TrustStrip primitive (which wraps TrustChips with optional leading PulseDot) and derives its signal states from already-loaded scan and risk data. No new backend endpoints required.

## Architecture

### New files

| File | Role |
|---|---|
| `web/components/layout/system-status-bar.tsx` | Visual bar component — wraps TrustStrip in a fixed-height bottom row |
| `web/features/dashboard/system-status.ts` | Pure function: `computeSystemStatus(risks, scans) → TrustSignal[]` + overall PulseDotTone |

### Modified files

| File | Change |
|---|---|
| `web/components/layout/app-shell.tsx` | Render `<SystemStatusBar />` between `<main>` and `<CommandPalette>` |

### No changes to

- PulseDot, TrustChip, TrustStrip (reused as-is)
- Header (ESTOP dot stays — different concern)
- Design tokens (all --pulse-* tokens already exist)

## Layout

```
┌─────────────────────────────────────────────────┐
│ Sidebar │ Header                                 │
│         ├────────────────────────────────────────┤
│         │ <main> (scrollable page content)       │
│         │                                        │
│         ├────────────────────────────────────────┤
│         │ SystemStatusBar (h-7, border-t, fixed) │
└─────────┴────────────────────────────────────────┘
```

- Height: `h-7` (28px) — same scale as a compact toolbar
- Background: `bg-card` to match the header
- Border: `border-t` to separate from main content
- Overflow: `overflow-x-auto` with `flex-wrap: nowrap` — horizontal scroll on narrow viewports instead of wrap
- Padding: `px-4` to align with the main content's `p-6` horizontal padding

## Signal Derivation

`computeSystemStatus(risks: RiskCluster[], scans: Scan[])` returns:

```typescript
interface SystemStatusResult {
  signals: TrustSignal[];
  overallPulse: PulseDotTone;
}
```

### Six signals

| # | Label | Data source | State derivation |
|---|---|---|---|
| 1 | Scans | `scans[].status` | All recent completed → `verified`. Any failed/timed_out → `pending`. Majority failed → `revoked` |
| 2 | Last scan: {ago} | `scans[].finished_at` | < 24h → `verified`. < 7d → `pending`. > 7d or never → `revoked` |
| 3 | Correlation | None (placeholder) | `unknown` |
| 4 | Webhooks | None (placeholder) | `unknown` |
| 5 | Data: {state} | `risks[].last_seen_at` | < 24h → `verified`. < 7d → `pending`. > 7d → `revoked` |
| 6 | CI/CD | None (placeholder) | `unknown` |

### Overall pulse

Derived from the worst **non-unknown** signal:
- Any `revoked` → `err` (red pulse)
- Any `pending` → `warn` (yellow pulse)
- All `verified` (or all unknown) → `ok` (green pulse)

### Thresholds

All time-based thresholds are defined as named constants at the top of `system-status.ts`:

```typescript
const FRESH_THRESHOLD_MS = 24 * 60 * 60 * 1000;   // 24 hours
const AGING_THRESHOLD_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
```

### Freshness formatting

Reuses the same `formatFreshness()` helper from `dashboard-stats.ts` — extracted to a shared utility or duplicated (2 lines, not worth a shared file).

## SystemStatusBar Component

```typescript
interface SystemStatusBarProps {
  className?: string;
}
```

Internally:
1. Calls `useScans({ limit: 10 })` and `useRisks({ project_id, status: "all", limit: 50 })` — React Query dedupes with the dashboard queries
2. Calls `computeSystemStatus(risks, scans)` to get the signal array + overall pulse
3. Renders `<TrustStrip signals={signals} overallPulse={overallPulse} className="flex-nowrap" />`
4. Wraps in `<div className="h-7 border-t bg-card px-4 flex items-center overflow-x-auto">`

### Loading state

While data loads, renders a single `<PulseDot tone="ok" pulsing={false} />` with a "Loading..." text — same quiet visual as the header's system-operational dot.

### Project context

The bar needs a `project_id` to query risks. It reads the same project state that the dashboard uses. Since AppShell doesn't currently hold project state (that's per-page), the bar either:
- Queries risks without a project filter (if the API supports it)
- Shows only scan-derived signals until a project is selected
- Reads the most recent project from a lightweight context

Recommended: show only scan-derived signals (Scans, Last scan) and the placeholders when no project context is available. Data freshness requires risks, so it shows as `unknown` outside project-scoped pages. This is honest and avoids adding a global project context just for the status bar.

## Styling

- TrustChips in the bar use `size="sm"` for density
- No pulsing on individual chips — only the overall leading PulseDot pulses
- The bar inherits the card background and border tokens — no new colours
- The `pulse-trust` animation on the leading dot is the only motion in the bar
- `prefers-reduced-motion` collapses the pulse to static (already handled by PulseDot)

## Accessibility

- The bar is `role="status"` with `aria-label="System status"` — screen readers announce it as a live region
- Each TrustChip has its own `aria-hidden` (decorative) or `aria-label` (when it's the sole signal)
- The overall PulseDot has `aria-label="System status: {ok|degraded|unhealthy}"`

## Graceful degradation

| Scenario | Behaviour |
|---|---|
| No scans data (API error) | Scans → `unknown`, Last scan → `unknown` |
| No risks data (no project) | Data → `unknown` |
| All signals unknown | Overall pulse → `ok` (green, quiet — "nothing is reporting a problem") |
| Emergency stop active | Bar is independent of ESTOP — the header handles that. Bar shows platform health, not governance actions |

## Testing considerations

- `computeSystemStatus` is a pure function — unit-testable with mock scan/risk arrays
- SystemStatusBar is a thin render wrapper — visual verification via dev server
- The bar should render correctly with empty arrays (all unknown), partial data, and full data

## Future extensions

When backend health endpoints land:
- Only `system-status.ts` changes — the component and primitives stay identical
- Correlation, webhook, CI/CD signals switch from `unknown` to real derivations
- No UI file changes needed
