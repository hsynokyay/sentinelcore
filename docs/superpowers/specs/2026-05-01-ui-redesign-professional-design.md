# SentinelCore UI Redesign — Professional Tier (Linear × Datadog)

**Status:** Design complete, awaiting implementation plan
**Owner:** Huseyin
**Target:** All 12 dashboard routes + login + design system tokens
**Reference:** Linear (craft, typography, motion) + Datadog (security/observability domain conventions, info density, severity language)

---

## 1. Goals & non-goals

### Goals
- Raise UI from "default shadcn template" to top-tier modern security-platform tier (Linear / Wiz / Vanta visual quality).
- Establish consistent design system: 4-layer surfaces, calibrated severity scale, typographic discipline, motion tokens used everywhere.
- Make every page legible "at a glance": insight first, evidence second.
- Default to dark mode (security-industry expectation); keep light mode functional.
- Polish detail pages (3-column rail/main/rail) — currently single-column long scrolls.
- Improve discoverability: keyboard, search, command palette as first-class affordances.

### Non-goals
- New features. Feature surface is unchanged; only presentation changes.
- Adding heavyweight chart libraries (recharts, d3). Hand-rolled SVG continues — Linear/Vercel pattern, ~0KB bundle cost.
- Redesigning the API or data shapes. Frontend-only.
- Backend/migration changes. Out of scope.
- Mobile-first redesign. Responsive breakpoints preserved at parity; mobile is best-effort, desktop-first.

---

## 2. Design principles

1. **Look first, count second.** Every card / table / chart leads with a one-sentence conclusion (`MicroInsight` primitive, already in use), then evidence. By the time the eye reaches the chart body, the reader knows what it says.
2. **Default dark, light opt-in.** Operators look at security dashboards for hours; dark reduces fatigue and matches industry expectation (Datadog, Snyk, Wiz, Vanta).
3. **Density is opt-in.** Tables default to "comfortable" (44px row); user can toggle "compact" (32px row) per page. Setting persists in localStorage.
4. **Severity is hue + icon.** Color alone is insufficient (color-blind users, monochrome printouts). Every severity treatment carries a paired icon (`AlertOctagon`, `AlertTriangle`, `Info`).

---

## 3. Design system: tokens

### 3.1 Surfaces (4 layers)

Current system has 2 layers (`background` + `card`); depth feels flat. New stack:

| Token            | Dark (oklch)               | Light (oklch)              | Usage                                    |
|------------------|----------------------------|----------------------------|------------------------------------------|
| `--bg`           | 0.135 0 0                  | 1 0 0                      | App background (body)                    |
| `--surface-1`    | 0.175 0 0                  | 0.99 0 0                   | Cards, table rows, sidebar               |
| `--surface-2`    | 0.215 0 0                  | 0.97 0 0                   | Hover, active, modals, toasts            |
| `--surface-3`    | 0.250 0 0                  | 0.94 0 0                   | Pressed, selected highlights, popovers   |

### 3.2 Borders (3 weights)

| Token              | Dark                           | Light                        | Usage                                   |
|--------------------|--------------------------------|------------------------------|-----------------------------------------|
| `--border-subtle`  | oklch(1 0 0 / 6%)              | oklch(0 0 0 / 5%)            | Zebra, dividers, inactive separators    |
| `--border`         | oklch(1 0 0 / 12%)             | oklch(0 0 0 / 10%)           | Card edges, default borders             |
| `--border-strong`  | oklch(1 0 0 / 20%)             | oklch(0 0 0 / 18%)           | Focus ring offset, selected, hover      |

### 3.3 Brand accent

Current `--primary` is a flat dark gray (`oklch(0.205 0 0)`) — visually inert.

New brand: **violet** matching the `ShieldCheck` logo personality.

| Token                         | Value                          |
|-------------------------------|--------------------------------|
| `--brand`                     | oklch(0.66 0.22 285)           |
| `--brand-foreground`          | oklch(0.99 0 0)                |
| `--brand-muted`               | oklch(0.66 0.22 285 / 12%)     |

`--brand` replaces `--primary` as the active/accent color across buttons, sidebar active state, focus ring, link hover.

### 3.4 Severity (calibrated, not redefined)

Existing `--severity-{critical,high,medium,low,info}` tokens are kept. Calibration: dark-mode chroma reduced ~5–8% to remove the over-saturated "neon" feel that prompted the "looks bad" feedback. Hues unchanged (red, amber, yellow, blue, slate) — Datadog-compatible.

### 3.5 Typography scale (8 steps)

Replaces ad-hoc `text-2xl`/`text-xl`/`text-sm`/`text-xs` mixing.

| Step          | Size / Line / Weight            | Use                                         |
|---------------|---------------------------------|---------------------------------------------|
| `display`     | 28px / 36 / 700                 | Login hero, marketing-style headers         |
| `h1`          | 22px / 28 / 600                 | Page titles                                 |
| `h2`          | 18px / 24 / 600                 | Section headers, modal titles               |
| `h3`          | 15px / 22 / 600                 | Card titles                                 |
| `body`        | 14px / 20 / 400                 | Default body                                |
| `body-sm`     | 13px / 18 / 400                 | Table cells (compact), captions             |
| `caption`     | 12px / 16 / 500 tracking-wide uppercase | Sidebar group headers, table headers |
| `mono`        | 12px / 16 / 400 tabular         | Hashes, IDs, counts in tables               |

`font-variant-numeric: tabular-nums` is **mandatory** on every numeric (scoreboard, table count, chart labels, delta chips).

### 3.6 Motion tokens

Existing tokens preserved and consistently applied:

```
--ease-out-sentinel: cubic-bezier(0.16, 1, 0.3, 1);
--duration-fast: 100ms;   /* hover, focus, dropdown open */
--duration-base: 150ms;   /* state changes, route transition */
--duration-slow: 250ms;   /* modal open/close */
--duration-score: 700ms;  /* score ring fill */
```

### 3.7 Focus ring

```css
.focus-ring {
  box-shadow:
    0 0 0 2px var(--bg),
    0 0 0 4px var(--brand);
}
```

Applied via `:focus-visible` (keyboard only) on every interactive element. Replaces default browser outline.

---

## 4. Layout

### 4.1 Sidebar (240px, was 224px)

**Grouped, three sections:**

```
─ Workspace switcher (project/org)         ← new, top
─

POSTURE                                     ← caption header
  ▸ Dashboard
  ▸ Findings
  ▸ Risks

SCANNING
  ▸ Scans
  ▸ Targets
  ▸ Auth Profiles
  ▸ Source Artifacts
  ▸ Attack Surface

OPERATIONS
  ▸ Approvals
  ▸ Notifications
  ▸ Audit Log
  ▸ Settings

─                                           ← footer
  v0.1.0 · org-name · prod                 ← env badge
  ⌘?  Keyboard shortcuts                    ← help shortcut
```

**Active link state:** soft `--surface-2` bg + `--foreground` text + 2px `--brand` left border. Replaces the louder "primary tinted bg + primary text" pattern.

**Workspace switcher:** Replaces the bare `<select>` currently in the dashboard page (line 71–82 of `app/(dashboard)/dashboard/page.tsx`). Project ID context is owned by the switcher and propagated via context — Dashboard page no longer renders its own selector.

### 4.2 Header

**Layout:**
```
[breadcrumbs ───]    [⌘K  Search…  ───]    [ESTOP] [🔔] [☀/🌙] [User ▾]
```

- **Breadcrumbs (left):** `Workspace › Risks › SQL injection in /api/users`. Built from `usePathname` + a route-to-label map. Critical for detail pages.
- **Command-palette trigger (center):** Full-input look (placeholder text + `⌘K` kbd badge). Replaces the small icon button. Massively improves discoverability — matches Cursor/Linear pattern.
- **ESTOP chip:** Existing logic preserved.
- **Notifications bell:** Count badge if unread.
- **Theme switcher:** Sun/moon toggle. Default dark.
- **User menu:** Avatar dropdown — name, role, settings, sign out. Replaces the current single logout icon.

### 4.3 Page shell

- **Container:** `max-w-[1440px]` centered, 24px page padding.
- **`PageHeader` rewritten:**
  ```
  Findings  (1,247)         [Severity: All ▾] [Status: Open ▾]    [Export ▾] [+ New Scan]
  ```
  - Title + count chip + filter chips inline.
  - Action buttons right-aligned.
  - Description (when provided) below title in muted text.
- **Sticky sub-header on scroll:** Filter chips + count chip stay pinned to viewport top during long-list scroll. Datadog standard.
- **Density toggle:** Top-right of every list page. Persists per-page in localStorage.

### 4.4 Detail pages — 3-column

Findings detail, Risks detail, Scans detail all adopt:

```
┌──────────────┬──────────────────────────┬──────────────┐
│  Left rail   │  Main                    │  Right rail  │
│  240px       │  flex                    │  320px       │
│              │                          │              │
│  Metadata    │  Description             │  Actions     │
│  - severity  │  Evidence                │  - resolve   │
│  - project   │  Code / request body     │  - mute      │
│  - scan id   │  Reproduction steps      │  - reopen    │
│  - dates     │  Remediation             │              │
│  - owner     │                          │  Related     │
│              │                          │  - linked    │
│              │                          │    findings  │
│              │                          │  - linked    │
│              │                          │    scans     │
└──────────────┴──────────────────────────┴──────────────┘
```

Single-column layouts on detail pages today are dense vertically and feel placeholder-y; the 3-column layout is the unmistakable "professional security tool" shape.

---

## 5. Primitives

### 5.1 Existing UI primitives (rewritten)

| Primitive | Changes |
|-----------|---------|
| `button.tsx` | Tactile feedback (`translateY(-0.5px)` hover, `0.5px` active), brand-violet primary, 36px height (was variable) |
| `input.tsx`  | 36px height, floating label option, error state with icon + micro-text |
| `select.tsx` | Replace native `<select>` usages app-wide (esp. dashboard project selector) |
| `label.tsx`  | Floating label variant for input pairings |
| `badge.tsx`  | 3 variants: `severity` (5 hues + icon), `status` (success/warning/error/neutral), `tag` (subtle neutral). Soft-fill style (bg/10) |
| `card.tsx`   | 4 variants: `default`, `interactive` (hover state), `stat` (number + delta + sparkline), `hero` (full-width dashboard) |
| `dialog.tsx` | Keep `modal='trap-focus'` (already shipped). 3 sizes: `sm` 400 / `md` 560 / `lg` 880. Standard footer `[Cancel] [Primary]` |
| `table.tsx`  | Sticky header, no-zebra default, hover state, sortable column support |

### 5.2 Existing security primitives (kept, calibrated)

| Primitive | Treatment |
|-----------|-----------|
| `MicroInsight` | Kept verbatim — already correct |
| `PulseDot` | Animation timing aligned to `--ease-out-sentinel` |
| `ScoreDisplay` / `ScoreRing` | Stroke width thinned for premium feel |
| `ContributionBar` | Bar height 6px → 4px |
| `ChangeSummaryStrip` | Each tile gains a sparkline |
| `SeverityStrip` | Recalibrated to new severity tokens, used as backbone for new `StackedBar` |
| `TrustStrip` / `TrustChip` | Width consistency, hover affordance |
| `DeltaChip`, `IntegratedLabel`, `InsightTooltip`, `NextBestAction` | Keep behavior; restyle to new tokens |

### 5.3 New primitives

1. **`Sparkline`** — `data: number[]`, `tone: 'neutral' | 'positive' | 'negative'`, default 60×24px SVG path. Used in stat cards and table cells (e.g., risk-score trend per row). Datadog-style micro-trend.
2. **`SeverityHeatmap`** — 7×24 grid (day × hour), opacity-scaled cells colored by dominant severity. Renders findings/risks density over the past week. New dashboard card.
3. **`StackedBar`** — Single-row stacked segments for severity distribution. Total count above, hover tooltip per segment. Replaces the current `SeverityDistributionChart` body.

### 5.4 Empty + loading states

- **Every list/chart** has a branded empty state: icon + 1-line explanation + CTA button.
  - Findings empty: "No findings yet. Run your first scan." → /scans
  - Risks empty: "No risks correlated yet. Risks appear after a SAST + DAST scan completes."
  - Scans empty: "No scans yet. Configure a target to start." → /targets
- **Loading:** Skeleton mirrors the actual layout (table skeleton has the right column widths and 8 rows; chart skeleton has axis lines).

---

## 6. Page-by-page treatment

### 6.1 Dashboard

**Hero strip (full-width):**
- Insight sentence + ChangeSummaryStrip (with sparklines)
- Severity StackedBar with breakdown table below

**3-column grid:**
- Top Risks card (existing) + Sparkline of risk count over time
- Runtime Confirmed card (existing) + delta + sparkline
- Public Exposure card (existing) + delta + sparkline

**SeverityHeatmap (new):** Full-width below the 3-column grid. "When did findings spike?"

### 6.2 Findings / Risks / Scans / Targets / Auth Profiles / Artifacts / Surface / Approvals / Notifications / Audit

Common shape:
- New `PageHeader` with count, filters, actions
- Sticky filter sub-header on scroll
- New `DataTable` (sticky header, density toggle, bulk select, row actions, sortable columns)
- Branded empty state

### 6.3 Detail pages (Findings/[id], Risks/[id], Scans/[id])

3-column layout (Section 4.4). Right rail actions surface the resolve/mute/reopen mutations more prominently than current single-column placement.

### 6.4 Settings

Two-column: left nav (sections: Profile, Workspace, Notifications, SSO, API Keys, Billing) + right content. Replaces flat single-page settings.

### 6.5 Login

Split-screen:
- Left 60%: hero — large logo + tagline + soft animated severity-tinted gradient
- Right 40%: 360px form card on `--surface-2`, modern field stack, SSO buttons placeholder (wired up in phase3-oidc branch)

---

## 7. Motion & microinteractions

| Element            | Interaction                                                         |
|--------------------|---------------------------------------------------------------------|
| Button             | Hover: `translateY(-0.5px)` + shadow upgrade. Active: `0.5px` press |
| Card (interactive) | Hover: `border-strong` + `surface-2` bg, 100ms                      |
| Table row          | Hover: `surface-2` bg + 2px brand left border                       |
| Sidebar link       | Hover: soft bg. Active: 2px brand left border + foreground text     |
| Toast (Sonner)     | Top-right, `surface-2` + `border-strong`                            |
| Skeleton shimmer   | Custom keyframe (left→right shine) replacing `animate-pulse`        |
| Page transition    | Next 16 view-transitions API, 150ms fade + slide-up                 |
| Dialog open/close  | 250ms fade + scale 0.95→1 with `ease-out-sentinel`                  |

---

## 8. Accessibility

- All severity treatments use **hue + icon**.
- `:focus-visible` rings on every interactive element.
- Color contrast: severity text on surface-1 verified ≥ AA. Calibration in §3.4 preserves this.
- Keyboard: Tab order matches visual order. Cmd+K opens command palette. `?` opens shortcut overlay (new).
- Screen-reader: every chart has `aria-label` with the insight sentence (the conclusion); the SVG body is `aria-hidden`.
- Reduced motion: `@media (prefers-reduced-motion)` disables transforms and shimmer; opacity transitions retained.

---

## 9. Implementation strategy

Six PRs, each independently deployable, each with its own image tag for rollback.

| PR | Scope | Files | Estimate |
|----|-------|-------|----------|
| 1 | Tokens — surface layers, brand violet, focus ring, calibrated severity, typography scale | `app/globals.css` only | 2h |
| 2 | UI primitives — button, input, select, label, badge, card, dialog, table | `components/ui/*` | 4h |
| 3 | Layout shell — sidebar grouping + workspace switcher, header breadcrumbs + center search, PageHeader rewrite, density toggle | `components/layout/*`, `components/data/page-header.tsx`, `(dashboard)/layout.tsx` | 4h |
| 4 | Data primitives — DataTable rewrite (sticky header, sortable, density, empty states), new `Sparkline` / `SeverityHeatmap` / `StackedBar` | `components/data/*`, `components/security/*` | 5h |
| 5 | Page-by-page — Dashboard hero composition, list pages with new filters/empty states, detail pages 3-column | `app/(dashboard)/**/*.tsx`, `features/*` | 6h |
| 6 | Login redesign + motion polish + final QA | `app/(auth)/login/page.tsx`, motion utilities, audit per-page | 2h |

**Branch strategy:** Work on `design/ui-revamp-2026-05` cut from current `phase2/api-dast` HEAD. Today's hotfix changes (`web/components/ui/dialog.tsx` modal='trap-focus' + `web/features/scans/create-scan-dialog.tsx` render-loop fix) are committed first on the source branch, then carried into the design branch.

**Deploy strategy:** Each PR builds a new image tag (`sentinelcore/frontend:redesign-pr1`, `…-pr2`, …). After QA on each, retag as `pilot`. The pre-redesign image is preserved as `sentinelcore/frontend:pilot-pre-redesign` for one-command rollback.

**QA per PR:**
- PR 1 (tokens): visual smoke test on every existing page — nothing should break, only colors shift
- PR 2 (primitives): every component used in app should still render — no API changes
- PR 3 (shell): sidebar grouping correct, breadcrumbs accurate, command palette unchanged
- PR 4 (data): tables sort, filter, paginate; charts render
- PR 5 (pages): each route loads, primary actions work
- PR 6 (login + motion): login flow end-to-end, no regressions

---

## 10. Risks & mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| `modal='trap-focus'` (already shipped today) means click-outside *can* close the dialog. May surprise users mid-form-fill | Medium | Add `disablePointerDismissal={true}` on form dialogs (CreateScanDialog, AuthProfileDialog, etc.). Confirm-style dialogs keep default. |
| Light mode fidelity drops below dark mode quality during redesign | Low | Default dark; light mode is "best-effort" — only fix critical contrast violations during the redesign. Full light-mode polish is a follow-up. |
| Workspace switcher introduces a new context boundary; pages currently read `projects[0]` directly | Medium | Switcher writes to a `WorkspaceContext`; `useProjectId()` hook reads from context with a fallback. Migrate page-by-page in PR 5. |
| Custom skeleton shimmer keyframe could regress on Safari | Low | Test on Safari before PR 4 merge; fall back to `animate-pulse` if needed. |
| Dashboard `<select>` removal breaks projects fetch ordering on dashboard | Low | Dashboard reads `useProjectId()` post-PR3; no functional regression — just relocates the control. |
| 6 PRs over 1.5–2 days is aggressive; user UX preference may diverge mid-stream | Medium | Each PR is independently shippable. After PR 1 + PR 2, present a screenshot; adjust direction before sinking effort into PRs 3–6. |

---

## 11. Open questions

(None — all addressed during brainstorming. Section reserved for issues found during implementation.)
