# System Status Bar — Design Spec

**Date:** 2026-04-13
**Status:** Draft (reviewed, issues resolved)
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
| `web/features/dashboard/system-status.ts` | Pure function: `computeSystemStatus(scans) → SystemStatusResult` |
| `web/lib/format.ts` | Shared `formatFreshness()` helper extracted from `dashboard-stats.ts` |

### Modified files

| File | Change |
|---|---|
| `web/components/layout/app-shell.tsx` | Render `<SystemStatusBar />` after `</main>` and before the closing `</div>` of the flex column (NOT before CommandPalette — that's a portal sibling outside the column) |
| `web/features/dashboard/dashboard-stats.ts` | Import `formatFreshness` from `lib/format.ts` instead of defining it locally |
| `web/components/security/trust-strip.tsx` | Add `nowrap?: boolean` prop — when true, applies `flex-nowrap` instead of `flex-wrap` |

### No changes to

- PulseDot, TrustChip (reused as-is)
- Header (ESTOP dot stays — different concern)
- Design tokens (all --pulse-* tokens already exist)

## Layout

The current AppShell structure is:
```tsx
<div className="flex h-screen overflow-hidden">
  <Sidebar />
  <div className="flex-1 flex flex-col overflow-hidden">   ← content column
    <Header />
    <main className="flex-1 overflow-y-auto p-6">{children}</main>
                                                              ← bar goes here
  </div>
  <CommandPalette />                                         ← portal, outside column
</div>
```

The bar goes **after `</main>` and before the closing `</div>` of the flex column.

- Height: `h-7` (28px) — same scale as a compact toolbar
- Background: `bg-card` to match the header
- Border: `border-t` to separate from main content
- The bar uses `flex items-center` (block-level flex, not `inline-flex`)
- `overflow-x-auto` for horizontal scroll on narrow viewports
- Padding: `px-4` to align with the main content's `p-6` horizontal padding

## Signal Derivation

`computeSystemStatus(scans: Scan[])` returns:

```typescript
interface SystemStatusResult {
  signals: TrustSignal[];
  overallPulse: PulseDotTone;
}
```

### Project context decision (FIRM)

The bar does NOT query risks. `useRisks` requires `project_id` (a required field in `RiskListFilters`, and the hook is `enabled: Boolean(filters.project_id)`) and AppShell has no global project state. Adding a global project context just for the status bar would be over-engineering.

Instead: the bar queries only `useScans({ limit: 10 })`. Scan data is project-independent. The "Data freshness" signal uses the most recent scan's `finished_at` as a proxy for data age — if scans are running, data is fresh. This avoids the `project_id` dependency entirely.

### Six signals

| # | Label | Data source | State derivation |
|---|---|---|---|
| 1 | Scans | Last 10 scans' `status` field | See "Scans health rule" below |
| 2 | Last scan: {ago} | Most recent scan's `finished_at` | < 24h → `verified`. < 7d → `pending`. > 7d or never → `revoked` |
| 3 | Correlation | None (placeholder) | Always `unknown` |
| 4 | Webhooks | None (placeholder) | Always `unknown` |
| 5 | Data: {state} | Most recent scan's `finished_at` (proxy) | Same thresholds as signal #2 |
| 6 | CI/CD | None (placeholder) | Always `unknown` |

### Scans health rule

The denominator is the last 10 scans (the `limit: 10` query result). The evaluation:

1. Filter to terminal-state scans: `completed`, `failed`, `cancelled`, `timed_out`.
2. If zero terminal scans → `unknown` (no data to judge).
3. Count failures: `failed` + `timed_out` count as failures. `cancelled` is ignored (user-initiated, not a health signal).
4. If zero failures → `verified` ("Healthy").
5. If failure rate < 50% → `pending` ("Degraded").
6. If failure rate >= 50% → `revoked` ("Failing").

### TrustState subset note

The function produces only 4 of the 5 `TrustState` values: `verified`, `pending`, `revoked`, `unknown`. The `expired` state is not used — it implies a previously-valid credential that has lapsed, which doesn't apply to platform health signals.

### Overall pulse

Derived from the worst **non-unknown** signal:
- Any `revoked` → `err` (red pulse)
- Any `pending` → `warn` (yellow pulse)
- All `verified` (or all unknown) → `ok` (green pulse)

### Thresholds

All time-based thresholds are named constants:

```typescript
const FRESH_MS  = 24 * 60 * 60 * 1000;  // 24 hours
const AGING_MS  = 7 * 24 * 60 * 60 * 1000; // 7 days
const FAILURE_THRESHOLD = 0.5; // 50% failure rate = "Failing"
```

### Freshness formatting

The `formatFreshness()` helper is extracted from `dashboard-stats.ts` to a new shared utility at `web/lib/format.ts`. Both `dashboard-stats.ts` and `system-status.ts` import from there. The function is 12 lines and non-trivial enough to warrant a shared location.

## SystemStatusBar Component

```typescript
interface SystemStatusBarProps {
  className?: string;
}
```

Internally:
1. Calls `useScans({ limit: 10 })` — React Query dedupes with the dashboard's scan query
2. Calls `computeSystemStatus(scans)` to get the signal array + overall pulse
3. Renders `<TrustStrip signals={signals} overallPulse={overallPulse} nowrap />`
4. Wraps in `<div className="h-7 border-t bg-card px-4 flex items-center overflow-x-auto">`

### Loading state

While data loads, renders a single static `<PulseDot tone="ok" pulsing={false} />` with "Loading…" text in muted-foreground — same quiet visual as the header's system-operational dot.

### Error state

When `useScans` returns `isError: true`, renders a static `<PulseDot tone="warn" pulsing={false} />` with "Status unavailable" text. Does NOT show "Loading…" for errors — that would be misleading.

## TrustStrip `nowrap` prop

Add a `nowrap?: boolean` prop to TrustStrip. When true:
- Applies `flex-nowrap` instead of the default `flex-wrap`
- Changes `inline-flex` to `flex` so the strip fills its container as a block-level flex child

This is cleaner than relying on className override ordering in Tailwind v4.

## Styling

- TrustChips in the bar use `size="sm"` for density
- No pulsing on individual chips — only the overall leading PulseDot pulses
- The bar inherits the card background and border tokens — no new colours
- The `pulse-trust` animation on the leading dot is the only motion in the bar
- `prefers-reduced-motion` collapses the pulse to static (already handled by PulseDot)

## Accessibility

- The bar is `role="status"` with `aria-label="System status"` and `aria-live="off"`
- `aria-live="off"` is explicit: we do NOT want screen readers announcing every signal change (scans can change state rapidly during a run, producing noisy announcements). Users discover the bar's state by navigating to it, not via live announcements.
- Each TrustChip has its own `aria-hidden` (decorative since the overall pulse carries the summary)
- The overall PulseDot has `aria-label="System status: {ok|degraded|unhealthy}"`

## Graceful degradation

| Scenario | Behaviour |
|---|---|
| Scans query loading | Bar shows "Loading…" with static green dot |
| Scans query error | Bar shows "Status unavailable" with static yellow dot |
| Empty scans array | All scan-derived signals → `unknown`, placeholders stay `unknown`, overall → `ok` |
| Emergency stop active | Bar is independent of ESTOP — the header handles that. Bar shows platform health, not governance actions |

## Testing considerations

- `computeSystemStatus` is a pure function — unit-testable with mock scan arrays
- Tests are deferred to a follow-up task (no test file in this scope)
- SystemStatusBar is a thin render wrapper — visual verification via dev server
- The bar should render correctly with: empty arrays, partial data, full data, error state

## Future extensions

When backend health endpoints land:
- Only `system-status.ts` changes — the component and primitives stay identical
- Correlation, webhook, CI/CD signals switch from `unknown` to real derivations
- Risk-based "Data freshness" can be added when a global project context is introduced
- No UI file changes needed
