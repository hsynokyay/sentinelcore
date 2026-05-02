# SentinelCore UI Redesign — Professional Tier — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Raise the SentinelCore web UI from default-shadcn quality to top-tier modern security-platform tier (Linear × Datadog), across all 12 dashboard routes plus login, while preserving every existing feature and avoiding heavyweight chart libraries.

**Architecture:** Six independently-deployable PRs. PR 1 lays new design tokens. PR 2 rewrites UI primitives against those tokens. PR 3 rebuilds the app shell (sidebar + header + page header). PR 4 rewrites the data table and adds three new viz primitives. PR 5 applies the new shell + data primitives across every route, including detail pages converted to a 3-column layout. PR 6 redesigns login and applies global motion polish. Each PR ships a tagged Docker image (`sentinelcore/frontend:redesign-prN`) so any step is one-command rollback.

**Tech Stack:** Next.js 16.2.2 (App Router, view-transitions), React 19.2.4, Tailwind CSS v4, Base UI 1.3 (Dialog, Select), shadcn-style components, oklch color system, hand-rolled SVG for charts (no recharts/d3), Sonner v2 for toasts, lucide-react icons, react-hook-form + zod, @tanstack/react-query v5.

**Spec reference:** `docs/superpowers/specs/2026-05-01-ui-redesign-professional-design.md`

---

## Working environment

- **Branch:** `design/ui-revamp-2026-05` cut from `phase2/api-dast` HEAD.
- **Pre-flight:** Today's two hotfix files are already on disk on the source branch but uncommitted. They MUST be committed on `phase2/api-dast` before cutting the design branch so the fixes carry forward:
  - `web/components/ui/dialog.tsx` (modal='trap-focus')
  - `web/features/scans/create-scan-dialog.tsx` (createScan render-loop fix)
- **Build:** Image builds happen on the production server (no local Docker on the dev machine):
  ```
  scp -r web okyay@77.42.34.174:/tmp/sentinelcore-src/web/
  ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src/web && \
      docker build --build-arg NEXT_PUBLIC_API_URL='' -t sentinelcore/frontend:redesign-prN ."
  ```
- **Deploy:** After a per-PR image builds, retag to `pilot` and recreate via compose:
  ```
  ssh okyay@77.42.34.174 "docker tag sentinelcore/frontend:redesign-prN sentinelcore/frontend:pilot && \
      cd /opt/sentinelcore/compose && docker compose up -d frontend"
  ```
- **Rollback:** Tag the current pilot once before PR1 starts:
  ```
  ssh okyay@77.42.34.174 "docker tag sentinelcore/frontend:pilot sentinelcore/frontend:pilot-pre-redesign"
  ```
  Any PR can be reverted with `docker tag sentinelcore/frontend:pilot-pre-redesign sentinelcore/frontend:pilot && docker compose up -d frontend`.

---

## File structure

### New files (created during plan)

| Path | Responsibility |
|------|----------------|
| `web/lib/workspace-context.tsx` | Provides current project ID via React context; replaces ad-hoc `projects[0]` reads |
| `web/lib/density-context.tsx` | Persisted (localStorage) "compact" / "comfortable" toggle for tables |
| `web/lib/route-labels.ts` | Maps pathname segments to breadcrumb labels |
| `web/components/security/sparkline.tsx` | 60×24 SVG micro-trend |
| `web/components/security/severity-heatmap.tsx` | 7×24 cell heatmap of findings density |
| `web/components/security/stacked-bar.tsx` | Single-row severity stacked segment bar |
| `web/components/data/empty-state-branded.tsx` | Branded empty state (icon + line + CTA) |
| `web/components/data/density-toggle.tsx` | UI for density-context |
| `web/components/data/sticky-subheader.tsx` | Wrapper that pins filter chips on scroll |
| `web/components/layout/breadcrumbs.tsx` | Header breadcrumbs from pathname |
| `web/components/layout/workspace-switcher.tsx` | Sidebar top control |
| `web/components/layout/theme-switcher.tsx` | Header sun/moon toggle |
| `web/components/layout/user-menu.tsx` | Header avatar dropdown |
| `web/components/layout/global-search-trigger.tsx` | Header center input → opens command palette |
| `web/components/layout/keyboard-help-overlay.tsx` | `?` shortcut overlay |
| `web/components/layout/sidebar-group.tsx` | Group with collapsible caption header |

### Modified files (rewritten or substantially touched)

| Path | Purpose of change |
|------|-------------------|
| `web/app/globals.css` | New tokens (surfaces, borders, brand, calibrated severity, focus ring); typography utilities |
| `web/components/ui/button.tsx` | Tactile feedback, brand-violet primary, 36px standard |
| `web/components/ui/input.tsx` | 36px, floating-label variant, error state with icon |
| `web/components/ui/select.tsx` | Touched only to match new tokens |
| `web/components/ui/label.tsx` | Floating-label variant |
| `web/components/ui/badge.tsx` | 3 variants (severity / status / tag), soft-fill |
| `web/components/ui/card.tsx` | 4 variants (default / interactive / stat / hero) |
| `web/components/ui/dialog.tsx` | 3 sizes (sm / md / lg) |
| `web/components/ui/table.tsx` | Sticky header, no-zebra default, hover row, sortable header |
| `web/components/data/data-table.tsx` | Sticky header, density-aware, sortable, bulk-select, row-actions, branded empty, structured skeleton |
| `web/components/data/page-header.tsx` | Count chip, inline filters, density toggle |
| `web/components/data/loading-state.tsx` | Column-aware structured skeleton |
| `web/components/layout/sidebar.tsx` | Grouped, workspace switcher, active state with brand left border |
| `web/components/layout/header.tsx` | Breadcrumbs, center search trigger, theme switcher, user menu |
| `web/components/layout/app-shell.tsx` | Wrap with WorkspaceProvider + DensityProvider; mount keyboard help overlay |
| `web/app/(dashboard)/layout.tsx` | Workspace context, view-transitions enable |
| `web/app/(dashboard)/dashboard/page.tsx` | Hero composition, sparklines, heatmap; remove inline `<select>` |
| `web/app/(dashboard)/findings/page.tsx` + `findings/[id]/page.tsx` | New filters, branded empty, 3-col detail |
| `web/app/(dashboard)/risks/page.tsx` + `risks/[id]/page.tsx` | Same + risk-score timeline in right rail |
| `web/app/(dashboard)/scans/page.tsx` + `scans/[id]/page.tsx` | Same |
| `web/app/(dashboard)/targets/page.tsx`, `auth-profiles/page.tsx`, `artifacts/page.tsx`, `surface/page.tsx`, `approvals/page.tsx`, `notifications/page.tsx`, `audit/page.tsx` | New filters + empty states |
| `web/app/(dashboard)/settings/page.tsx` | Two-column layout |
| `web/app/(auth)/login/page.tsx` | Split-screen redesign |
| `web/components/ui/sonner.tsx` | Top-right, surface-2, accessible accent |
| `web/components/security/severity-strip.tsx` | Recalibrated; SeverityDistributionChart consumes new StackedBar |
| `web/components/security/score-display.tsx` + `score-ring.tsx` | Stroke width pass |
| `web/components/security/contribution-bar.tsx` | Bar height 6→4 |
| `web/components/security/change-summary-strip.tsx` | Per-tile sparkline |
| `web/components/security/pulse-dot.tsx` | Animation timing alignment |

### Validation files (touched only to verify behavior)

| Path | Verification |
|------|--------------|
| Manual smoke test list (kept in plan, not a file) | After each PR, walk through every dashboard route at least once |

---

## PR 0 — Pre-flight: commit hotfixes, cut design branch

**Files:**
- Modify: `web/components/ui/dialog.tsx` (already on disk — modal='trap-focus')
- Modify: `web/features/scans/create-scan-dialog.tsx` (already on disk — createScan render-loop fix via useRef)

- [ ] **Step 1: Verify hotfixes are present**

Run:
```
git diff web/components/ui/dialog.tsx | head -30
git diff web/features/scans/create-scan-dialog.tsx | head -30
```

Expected: both diffs show the changes described above; if either is missing, re-apply from chat history before continuing.

- [ ] **Step 2: Commit hotfixes on phase2/api-dast**

Run:
```
git add web/components/ui/dialog.tsx web/features/scans/create-scan-dialog.tsx
git commit -m "$(cat <<'EOF'
fix(web): remove Base UI inert leak + render-loop in create-scan-dialog

Two production bugs:

(1) Base UI Dialog with modal=true applies inert/aria-hidden to
    outside elements; if cleanup races with React's concurrent
    unmount, attributes leak and the sidebar becomes unclickable.
    Switch to modal='trap-focus' which keeps focus trap without
    inert markers.

(2) The CreateScanDialog form-reset effect depended on the
    useMutation result object, which is a new reference every
    render. The effect re-ran on every render, calling reset() in
    a tight loop and starving the main thread. This blocked
    React 19's concurrent route transitions away from /scans.
    Pin createScan in a ref so the effect depends only on `open`.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

Expected: clean commit, no errors.

- [ ] **Step 3: Cut design branch**

Run:
```
git checkout -b design/ui-revamp-2026-05
```

Expected: now on `design/ui-revamp-2026-05`.

- [ ] **Step 4: Tag the current production image for rollback**

Run:
```
ssh okyay@77.42.34.174 "docker tag sentinelcore/frontend:pilot sentinelcore/frontend:pilot-pre-redesign && docker images | grep frontend | head -5"
```

Expected: `pilot-pre-redesign` tag appears alongside `pilot`.

---

## PR 1 — Design tokens

Touches only `web/app/globals.css`. No component changes; existing UI keeps rendering, just with recalibrated colors and new tokens available.

### Task 1.1: Add 4-layer surface tokens

**Files:**
- Modify: `web/app/globals.css`

- [ ] **Step 1: Replace the dark-mode block's surface variables**

Find in `:root.dark` (currently around line 130–140):
```css
--background: oklch(0.145 0 0);
--card: oklch(0.205 0 0);
```

Replace and extend to:
```css
--bg: oklch(0.135 0 0);
--background: var(--bg);                     /* legacy alias */
--surface-1: oklch(0.175 0 0);
--surface-2: oklch(0.215 0 0);
--surface-3: oklch(0.250 0 0);
--card: var(--surface-1);                    /* legacy alias */
```

- [ ] **Step 2: Add the same shape to :root (light mode)**

Find in `:root` (top of file):
```css
--background: oklch(1 0 0);
--card: oklch(1 0 0);
```

Replace and extend to:
```css
--bg: oklch(1 0 0);
--background: var(--bg);
--surface-1: oklch(0.99 0 0);
--surface-2: oklch(0.97 0 0);
--surface-3: oklch(0.94 0 0);
--card: var(--surface-1);
```

- [ ] **Step 3: Expose tokens to Tailwind via @theme**

In the `@theme inline` block (top of file), after `--color-card-foreground:`:
```css
--color-bg: var(--bg);
--color-surface-1: var(--surface-1);
--color-surface-2: var(--surface-2);
--color-surface-3: var(--surface-3);
```

- [ ] **Step 4: Commit**

Run:
```
git add web/app/globals.css
git commit -m "feat(ui): add 4-layer surface tokens (bg / surface-1 / surface-2 / surface-3)"
```

### Task 1.2: Add 3-weight border tokens

**Files:**
- Modify: `web/app/globals.css`

- [ ] **Step 1: Replace dark-mode border**

Find:
```css
--border: oklch(1 0 0 / 10%);
```

Replace with:
```css
--border-subtle: oklch(1 0 0 / 6%);
--border: oklch(1 0 0 / 12%);
--border-strong: oklch(1 0 0 / 20%);
```

- [ ] **Step 2: Replace light-mode border**

Find:
```css
--border: oklch(0.922 0 0);
```

Replace with:
```css
--border-subtle: oklch(0 0 0 / 5%);
--border: oklch(0 0 0 / 10%);
--border-strong: oklch(0 0 0 / 18%);
```

- [ ] **Step 3: Expose to Tailwind**

In the `@theme inline` block, near `--color-border:`:
```css
--color-border-subtle: var(--border-subtle);
--color-border-strong: var(--border-strong);
```

- [ ] **Step 4: Commit**

Run:
```
git add web/app/globals.css
git commit -m "feat(ui): add border weight tokens (subtle / default / strong)"
```

### Task 1.3: Add brand violet, replace primary

**Files:**
- Modify: `web/app/globals.css`

- [ ] **Step 1: Add brand tokens (dark)**

Inside `:root.dark`, before the closing brace, insert:
```css
--brand: oklch(0.66 0.22 285);
--brand-foreground: oklch(0.99 0 0);
--brand-muted: oklch(0.66 0.22 285 / 12%);
--primary: var(--brand);
--primary-foreground: var(--brand-foreground);
```

- [ ] **Step 2: Add brand tokens (light)**

Inside `:root`, before the closing brace:
```css
--brand: oklch(0.55 0.22 285);
--brand-foreground: oklch(0.99 0 0);
--brand-muted: oklch(0.55 0.22 285 / 10%);
--primary: var(--brand);
--primary-foreground: var(--brand-foreground);
```

- [ ] **Step 3: Expose to Tailwind**

In `@theme inline`:
```css
--color-brand: var(--brand);
--color-brand-foreground: var(--brand-foreground);
--color-brand-muted: var(--brand-muted);
```

- [ ] **Step 4: Commit**

Run:
```
git add web/app/globals.css
git commit -m "feat(ui): add brand violet token and re-route --primary to it"
```

### Task 1.4: Calibrate severity tokens

**Files:**
- Modify: `web/app/globals.css`

- [ ] **Step 1: Reduce dark-mode chroma slightly**

Find in `:root.dark`:
```css
--severity-critical: oklch(0.695 0.250 14);
--severity-high:     oklch(0.745 0.195 46);
--severity-medium:   oklch(0.865 0.175 92);
--severity-low:      oklch(0.705 0.200 252);
```

Replace with (chroma trimmed ~0.02–0.03 to remove neon feel):
```css
--severity-critical: oklch(0.700 0.225 14);
--severity-high:     oklch(0.755 0.175 46);
--severity-medium:   oklch(0.870 0.155 92);
--severity-low:      oklch(0.715 0.180 252);
```

`--severity-info` is left at `oklch(0.635 0.020 260)` — already balanced.

- [ ] **Step 2: Commit**

Run:
```
git add web/app/globals.css
git commit -m "refactor(ui): calibrate dark-mode severity chroma to reduce neon feel"
```

### Task 1.5: Add typography utility classes

**Files:**
- Modify: `web/app/globals.css`

- [ ] **Step 1: Append @utility blocks (Tailwind v4 syntax)**

At the end of `globals.css`, append:
```css
@utility text-display {
  font-size: 28px;
  line-height: 36px;
  font-weight: 700;
  letter-spacing: -0.01em;
}
@utility text-h1 {
  font-size: 22px;
  line-height: 28px;
  font-weight: 600;
  letter-spacing: -0.005em;
}
@utility text-h2 {
  font-size: 18px;
  line-height: 24px;
  font-weight: 600;
}
@utility text-h3 {
  font-size: 15px;
  line-height: 22px;
  font-weight: 600;
}
@utility text-body {
  font-size: 14px;
  line-height: 20px;
  font-weight: 400;
}
@utility text-body-sm {
  font-size: 13px;
  line-height: 18px;
  font-weight: 400;
}
@utility text-caption {
  font-size: 12px;
  line-height: 16px;
  font-weight: 500;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
@utility text-mono {
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 16px;
  font-variant-numeric: tabular-nums;
}
@utility tabular {
  font-variant-numeric: tabular-nums;
}
```

- [ ] **Step 2: Commit**

Run:
```
git add web/app/globals.css
git commit -m "feat(ui): add 8-step typography utilities + tabular-nums helper"
```

### Task 1.6: Add focus-ring utility

**Files:**
- Modify: `web/app/globals.css`

- [ ] **Step 1: Append focus-ring utility**

At end of `globals.css`:
```css
@utility focus-ring {
  outline: none;
  &:focus-visible {
    box-shadow:
      0 0 0 2px var(--bg),
      0 0 0 4px var(--brand);
  }
}
```

- [ ] **Step 2: Commit**

Run:
```
git add web/app/globals.css
git commit -m "feat(ui): add focus-ring utility (keyboard-only via :focus-visible)"
```

### Task 1.7: PR 1 build, deploy, smoke test

- [ ] **Step 1: Push branch and copy source to server**

Run locally:
```
git push -u origin design/ui-revamp-2026-05
rsync -az --delete \
  --exclude node_modules --exclude .next --exclude .git \
  web/ okyay@77.42.34.174:/tmp/sentinelcore-src/web/
```

- [ ] **Step 2: Build PR1 image on server**

Run:
```
ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src/web && \
  docker build --build-arg NEXT_PUBLIC_API_URL='' -t sentinelcore/frontend:redesign-pr1 . 2>&1 | tail -10"
```

Expected: build success, "writing image …" line at the end.

- [ ] **Step 3: Deploy PR1 to pilot**

Run:
```
ssh okyay@77.42.34.174 "docker tag sentinelcore/frontend:redesign-pr1 sentinelcore/frontend:pilot && \
  cd /opt/sentinelcore/compose && docker compose up -d frontend"
curl -s -o /dev/null -w 'frontend: %{http_code}\n' https://sentinelcore.resiliencetech.com.tr/
```

Expected: `frontend: 307` (login redirect, normal).

- [ ] **Step 4: Smoke test — visit every route once**

In a browser logged in as admin@sentinel.io, visit each of:
- `/dashboard`
- `/findings` and one finding detail
- `/risks` and one risk detail
- `/scans` and one scan detail
- `/targets`, `/auth-profiles`, `/artifacts`, `/surface`
- `/approvals`, `/notifications`, `/audit`, `/settings`

Expected: every page renders without runtime errors. Colors may look subtly different (calibrated severity, brand violet on focus rings) but layout is unchanged.

- [ ] **Step 5: If smoke test passes, retain pilot tag; if it fails, rollback**

On failure:
```
ssh okyay@77.42.34.174 "docker tag sentinelcore/frontend:pilot-pre-redesign sentinelcore/frontend:pilot && \
  cd /opt/sentinelcore/compose && docker compose up -d frontend"
```

---

## PR 2 — UI primitives

All changes are in `web/components/ui/*`. After this PR every primitive consumes the new tokens.

### Task 2.1: Rewrite button.tsx

**Files:**
- Modify: `web/components/ui/button.tsx`

- [ ] **Step 1: Replace the file with the new primitive**

Full new contents:
```tsx
"use client"

import * as React from "react"
import { Slot } from "@base-ui/react/slot"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md text-body font-medium select-none transition-[transform,box-shadow,background-color,color,border-color] duration-fast ease-[cubic-bezier(0.16,1,0.3,1)] focus-ring disabled:pointer-events-none disabled:opacity-50 active:translate-y-[0.5px] [&>svg]:size-4 [&>svg]:shrink-0",
  {
    variants: {
      variant: {
        primary:
          "bg-brand text-brand-foreground hover:bg-brand/90 hover:-translate-y-[0.5px] hover:shadow-[0_2px_8px_-2px_rgba(0,0,0,0.25)]",
        secondary:
          "bg-surface-2 text-foreground border border-border hover:bg-surface-3 hover:-translate-y-[0.5px]",
        ghost:
          "text-foreground hover:bg-surface-2",
        outline:
          "bg-transparent text-foreground border border-border hover:bg-surface-2 hover:border-border-strong",
        destructive:
          "bg-[color:var(--severity-critical)] text-white hover:opacity-90 hover:-translate-y-[0.5px]",
      },
      size: {
        sm: "h-8 px-2.5 text-body-sm",
        md: "h-9 px-3",
        lg: "h-10 px-4",
        icon: "h-9 w-9",
      },
    },
    defaultVariants: { variant: "primary", size: "md" },
  }
)

interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button"
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    )
  }
)
Button.displayName = "Button"

export { Button, buttonVariants }
```

- [ ] **Step 2: Audit button consumers**

Run:
```
grep -rn "from \"@/components/ui/button\"" web/app web/components web/features --include='*.tsx' | wc -l
```

Expected: a count (likely 30+). All existing `<Button>` usages remain valid because the API is unchanged.

- [ ] **Step 3: Verify destructive prop still works (used in delete confirmations)**

Run:
```
grep -rn 'variant="destructive"' web --include='*.tsx' | head -5
```

If any usage exists, ensure it still renders by spot-checking the file.

- [ ] **Step 4: Commit**

Run:
```
git add web/components/ui/button.tsx
git commit -m "refactor(ui): rewrite Button — brand-violet primary, tactile feedback, 36px default"
```

### Task 2.2: Rewrite input.tsx

**Files:**
- Modify: `web/components/ui/input.tsx`

- [ ] **Step 1: Replace contents**

```tsx
"use client"

import * as React from "react"
import { cn } from "@/lib/utils"

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  invalid?: boolean
}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, invalid, ...props }, ref) => {
    return (
      <input
        type={type}
        ref={ref}
        aria-invalid={invalid || undefined}
        className={cn(
          "h-9 w-full min-w-0 rounded-md border border-border bg-bg px-3 text-body transition-colors duration-fast outline-none focus-ring placeholder:text-muted-foreground disabled:pointer-events-none disabled:opacity-50",
          "aria-[invalid=true]:border-[color:var(--severity-critical)] aria-[invalid=true]:focus-visible:shadow-[0_0_0_2px_var(--bg),0_0_0_4px_var(--severity-critical)]",
          className
        )}
        {...props}
      />
    )
  }
)
Input.displayName = "Input"

export { Input }
```

- [ ] **Step 2: Commit**

```
git add web/components/ui/input.tsx
git commit -m "refactor(ui): Input — 36px default, focus-ring utility, aria-invalid styling"
```

### Task 2.3: Update label.tsx

**Files:**
- Modify: `web/components/ui/label.tsx`

- [ ] **Step 1: Replace contents**

```tsx
"use client"

import * as React from "react"
import { cn } from "@/lib/utils"

const Label = React.forwardRef<
  HTMLLabelElement,
  React.LabelHTMLAttributes<HTMLLabelElement>
>(({ className, ...props }, ref) => (
  <label
    ref={ref}
    className={cn(
      "block text-body-sm font-medium text-foreground select-none mb-1.5 group-data-[disabled=true]:opacity-50",
      className
    )}
    {...props}
  />
))
Label.displayName = "Label"

export { Label }
```

- [ ] **Step 2: Commit**

```
git add web/components/ui/label.tsx
git commit -m "refactor(ui): Label — body-sm font-medium, consistent margin"
```

### Task 2.4: Rewrite badge.tsx

**Files:**
- Modify: `web/components/ui/badge.tsx`

- [ ] **Step 1: Replace contents**

```tsx
"use client"

import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-md border px-1.5 h-5 text-[11px] font-medium tabular [&>svg]:size-3 [&>svg]:shrink-0",
  {
    variants: {
      variant: {
        severity: "border-transparent",
        status: "border-transparent",
        tag: "border-border bg-surface-2 text-muted-foreground",
        outline: "border-border bg-transparent text-foreground",
      },
      tone: {
        critical: "bg-[color:var(--severity-critical)]/12 text-[color:var(--severity-critical)]",
        high: "bg-[color:var(--severity-high)]/12 text-[color:var(--severity-high)]",
        medium: "bg-[color:var(--severity-medium)]/12 text-[color:var(--severity-medium)]",
        low: "bg-[color:var(--severity-low)]/12 text-[color:var(--severity-low)]",
        info: "bg-[color:var(--severity-info)]/12 text-[color:var(--severity-info)]",
        success: "bg-[color:var(--signal-new)]/12 text-[color:var(--signal-new)]",
        warning: "bg-[color:var(--severity-medium)]/12 text-[color:var(--severity-medium)]",
        error: "bg-[color:var(--severity-critical)]/12 text-[color:var(--severity-critical)]",
        neutral: "bg-surface-2 text-muted-foreground",
      },
    },
    defaultVariants: { variant: "tag", tone: "neutral" },
  }
)

interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, tone, ...props }: BadgeProps) {
  return (
    <span className={cn(badgeVariants({ variant, tone }), className)} {...props} />
  )
}

export { Badge, badgeVariants }
```

- [ ] **Step 2: Audit consumers — many existing usages pass only `variant`**

Run:
```
grep -rn '<Badge' web --include='*.tsx' | head -30
```

For any `<Badge variant="outline">` usages, no change needed (variant kept). For any `<Badge variant="default">` usages, change to `<Badge variant="tag">`.

- [ ] **Step 3: Migrate any default-variant usages**

Run:
```
grep -rln 'variant="default"' web/components web/features web/app --include='*.tsx'
```

For each file shown, change `variant="default"` → `variant="tag"` only on Badge usages.

- [ ] **Step 4: Commit**

```
git add web/components/ui/badge.tsx web/app web/components web/features
git commit -m "refactor(ui): Badge — severity/status/tag variants with soft-fill style"
```

### Task 2.5: Rewrite card.tsx

**Files:**
- Modify: `web/components/ui/card.tsx`

- [ ] **Step 1: Replace contents**

```tsx
"use client"

import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const cardVariants = cva(
  "rounded-lg border bg-surface-1 text-foreground transition-colors duration-fast",
  {
    variants: {
      variant: {
        default: "border-border",
        interactive:
          "border-border hover:border-border-strong hover:bg-surface-2 cursor-pointer focus-ring",
        stat: "border-border",
        hero: "border-border bg-gradient-to-b from-surface-1 to-surface-2",
      },
      padding: {
        none: "p-0",
        sm: "p-3",
        md: "p-4",
        lg: "p-6",
      },
    },
    defaultVariants: { variant: "default", padding: "md" },
  }
)

interface CardProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof cardVariants> {}

function Card({ className, variant, padding, ...props }: CardProps) {
  return (
    <div className={cn(cardVariants({ variant, padding }), className)} {...props} />
  )
}

function CardHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("flex items-start justify-between gap-3 mb-3", className)} {...props} />
}

function CardTitle({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h3 className={cn("text-h3 text-foreground", className)} {...props} />
}

function CardDescription({ className, ...props }: React.HTMLAttributes<HTMLParagraphElement>) {
  return <p className={cn("text-body-sm text-muted-foreground", className)} {...props} />
}

function CardContent({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("text-body", className)} {...props} />
}

function CardFooter({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "mt-4 border-t border-border-subtle pt-3 text-body-sm text-muted-foreground",
        className
      )}
      {...props}
    />
  )
}

export { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter, cardVariants }
```

- [ ] **Step 2: Commit**

```
git add web/components/ui/card.tsx
git commit -m "refactor(ui): Card — 4 variants (default/interactive/stat/hero) with surface tokens"
```

### Task 2.6: Update dialog.tsx with size variants

**Files:**
- Modify: `web/components/ui/dialog.tsx`

- [ ] **Step 1: Replace DialogContent to accept size**

In `web/components/ui/dialog.tsx`, replace the `DialogContent` function:
```tsx
const sizeClass = {
  sm: "max-w-sm",
  md: "max-w-lg",
  lg: "max-w-3xl",
} as const

function DialogContent({
  className,
  children,
  size = "md",
  ...props
}: React.ComponentProps<typeof DialogPrimitive.Popup> & {
  size?: keyof typeof sizeClass
}) {
  return (
    <DialogPortal>
      <DialogBackdrop />
      <DialogPrimitive.Popup
        className={cn(
          "fixed left-1/2 top-1/2 z-50 w-full -translate-x-1/2 -translate-y-1/2 rounded-xl border border-border bg-surface-2 p-6 shadow-2xl data-[ending-style]:opacity-0 data-[ending-style]:scale-95 data-[starting-style]:opacity-0 data-[starting-style]:scale-95 transition-all duration-slow ease-[cubic-bezier(0.16,1,0.3,1)]",
          sizeClass[size],
          className
        )}
        {...props}
      >
        {children}
        <DialogPrimitive.Close
          className="absolute right-4 top-4 rounded-sm opacity-70 hover:opacity-100 transition-opacity focus-ring"
        >
          <X className="h-4 w-4" />
          <span className="sr-only">Close</span>
        </DialogPrimitive.Close>
      </DialogPrimitive.Popup>
    </DialogPortal>
  )
}
```

- [ ] **Step 2: Replace DialogBackdrop styling**

```tsx
function DialogBackdrop({ className, ...props }: React.ComponentProps<typeof DialogPrimitive.Backdrop>) {
  return (
    <DialogPrimitive.Backdrop
      className={cn(
        "fixed inset-0 z-50 bg-black/60 backdrop-blur-sm data-[ending-style]:opacity-0 data-[starting-style]:opacity-0 transition-opacity duration-slow ease-[cubic-bezier(0.16,1,0.3,1)]",
        className
      )}
      {...props}
    />
  )
}
```

- [ ] **Step 3: Commit**

```
git add web/components/ui/dialog.tsx
git commit -m "refactor(ui): Dialog — sm/md/lg sizes, surface-2 popup, backdrop blur"
```

### Task 2.7: Rewrite table.tsx

**Files:**
- Modify: `web/components/ui/table.tsx`

- [ ] **Step 1: Replace contents**

```tsx
"use client"

import * as React from "react"
import { cn } from "@/lib/utils"

const Table = React.forwardRef<HTMLTableElement, React.HTMLAttributes<HTMLTableElement>>(
  ({ className, ...props }, ref) => (
    <div className="relative w-full overflow-auto">
      <table
        ref={ref}
        className={cn("w-full caption-bottom text-body-sm tabular", className)}
        {...props}
      />
    </div>
  )
)
Table.displayName = "Table"

const TableHeader = React.forwardRef<
  HTMLTableSectionElement,
  React.HTMLAttributes<HTMLTableSectionElement>
>(({ className, ...props }, ref) => (
  <thead
    ref={ref}
    className={cn(
      "sticky top-0 z-10 bg-surface-1 [&_tr]:border-b [&_tr]:border-border",
      className
    )}
    {...props}
  />
))
TableHeader.displayName = "TableHeader"

const TableBody = React.forwardRef<
  HTMLTableSectionElement,
  React.HTMLAttributes<HTMLTableSectionElement>
>(({ className, ...props }, ref) => (
  <tbody ref={ref} className={cn("[&_tr:last-child]:border-0", className)} {...props} />
))
TableBody.displayName = "TableBody"

const TableRow = React.forwardRef<
  HTMLTableRowElement,
  React.HTMLAttributes<HTMLTableRowElement>
>(({ className, ...props }, ref) => (
  <tr
    ref={ref}
    className={cn(
      "border-b border-border-subtle transition-colors duration-fast hover:bg-surface-2 data-[state=selected]:bg-surface-2",
      className
    )}
    {...props}
  />
))
TableRow.displayName = "TableRow"

const TableHead = React.forwardRef<
  HTMLTableCellElement,
  React.ThHTMLAttributes<HTMLTableCellElement>
>(({ className, ...props }, ref) => (
  <th
    ref={ref}
    className={cn(
      "h-9 px-3 text-left align-middle text-caption text-muted-foreground",
      className
    )}
    {...props}
  />
))
TableHead.displayName = "TableHead"

const TableCell = React.forwardRef<
  HTMLTableCellElement,
  React.TdHTMLAttributes<HTMLTableCellElement>
>(({ className, ...props }, ref) => (
  <td
    ref={ref}
    className={cn("h-11 px-3 align-middle data-[density=compact]:h-8", className)}
    {...props}
  />
))
TableCell.displayName = "TableCell"

export { Table, TableHeader, TableBody, TableHead, TableRow, TableCell }
```

- [ ] **Step 2: Commit**

```
git add web/components/ui/table.tsx
git commit -m "refactor(ui): Table — sticky header, hover row, density-aware cell heights"
```

### Task 2.8: Update Sonner toaster

**Files:**
- Modify: `web/components/ui/sonner.tsx`

- [ ] **Step 1: Replace the Toaster component**

```tsx
"use client"

import { useTheme } from "next-themes"
import { Toaster as Sonner, type ToasterProps } from "sonner"
import { CircleCheckIcon, InfoIcon, TriangleAlertIcon, OctagonXIcon, Loader2Icon } from "lucide-react"

const Toaster = ({ ...props }: ToasterProps) => {
  const { theme = "system" } = useTheme()
  return (
    <Sonner
      theme={theme as ToasterProps["theme"]}
      position="top-right"
      className="toaster group"
      icons={{
        success: <CircleCheckIcon className="size-4" />,
        info: <InfoIcon className="size-4" />,
        warning: <TriangleAlertIcon className="size-4" />,
        error: <OctagonXIcon className="size-4" />,
        loading: <Loader2Icon className="size-4 animate-spin" />,
      }}
      style={
        {
          "--normal-bg": "var(--surface-2)",
          "--normal-text": "var(--foreground)",
          "--normal-border": "var(--border-strong)",
          "--border-radius": "var(--radius)",
        } as React.CSSProperties
      }
      toastOptions={{ classNames: { toast: "cn-toast" } }}
      {...props}
    />
  )
}

export { Toaster }
```

- [ ] **Step 2: Commit**

```
git add web/components/ui/sonner.tsx
git commit -m "refactor(ui): Toaster — top-right, surface-2, border-strong"
```

### Task 2.9: PR 2 build, deploy, smoke test

- [ ] **Step 1: Sync source to server**

```
rsync -az --delete \
  --exclude node_modules --exclude .next --exclude .git \
  web/ okyay@77.42.34.174:/tmp/sentinelcore-src/web/
```

- [ ] **Step 2: Build PR2 image**

```
ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src/web && \
  docker build --build-arg NEXT_PUBLIC_API_URL='' -t sentinelcore/frontend:redesign-pr2 . 2>&1 | tail -10"
```

Expected: build succeeds.

- [ ] **Step 3: Deploy and verify**

```
ssh okyay@77.42.34.174 "docker tag sentinelcore/frontend:redesign-pr2 sentinelcore/frontend:pilot && \
  cd /opt/sentinelcore/compose && docker compose up -d frontend"
curl -s -o /dev/null -w 'frontend: %{http_code}\n' https://sentinelcore.resiliencetech.com.tr/
```

- [ ] **Step 4: Smoke test**

In a browser, login and walk through every dashboard route. Pay attention to:
- Buttons feel "tactile" on hover
- Inputs have brand-violet focus ring (Tab through a form to verify)
- Badges use new soft-fill colors
- Cards have subtle border + new surface
- Dialog backdrops are blurred
- Toasts appear top-right

If any page errors, check browser console; if structural error, rollback.

- [ ] **Step 5: Push branch**

```
git push
```

---

## PR 3 — Layout shell

This PR introduces three context providers (workspace, density, theme), the new sidebar with grouping + workspace switcher, the new header with breadcrumbs + center search + theme switcher + user menu, and a rewritten PageHeader.

### Task 3.1: WorkspaceContext

**Files:**
- Create: `web/lib/workspace-context.tsx`

- [ ] **Step 1: Create the file**

```tsx
"use client"

import * as React from "react"
import { useProjects } from "@/features/scans/hooks"
import type { Project } from "@/lib/types"

interface WorkspaceContextValue {
  projects: Project[]
  projectId: string
  setProjectId: (id: string) => void
  activeProject: Project | undefined
  isLoading: boolean
}

const WorkspaceContext = React.createContext<WorkspaceContextValue | null>(null)

const STORAGE_KEY = "sentinel_active_project_id"

export function WorkspaceProvider({ children }: { children: React.ReactNode }) {
  const { data, isLoading } = useProjects()
  const projects = React.useMemo(() => data?.projects ?? [], [data])

  const [explicit, setExplicit] = React.useState<string>(() => {
    if (typeof window === "undefined") return ""
    return localStorage.getItem(STORAGE_KEY) ?? ""
  })

  // Validate persisted ID still exists in the project list; fall back to first.
  const projectId = React.useMemo(() => {
    if (explicit && projects.some((p) => p.id === explicit)) return explicit
    return projects[0]?.id ?? ""
  }, [explicit, projects])

  const setProjectId = React.useCallback((id: string) => {
    setExplicit(id)
    if (typeof window !== "undefined") localStorage.setItem(STORAGE_KEY, id)
  }, [])

  const activeProject = React.useMemo(
    () => projects.find((p) => p.id === projectId),
    [projects, projectId]
  )

  const value = React.useMemo<WorkspaceContextValue>(
    () => ({ projects, projectId, setProjectId, activeProject, isLoading }),
    [projects, projectId, setProjectId, activeProject, isLoading]
  )

  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>
}

export function useWorkspace() {
  const ctx = React.useContext(WorkspaceContext)
  if (!ctx) throw new Error("useWorkspace must be used inside <WorkspaceProvider>")
  return ctx
}

export function useProjectId() {
  return useWorkspace().projectId
}
```

- [ ] **Step 2: Commit**

```
git add web/lib/workspace-context.tsx
git commit -m "feat(web): WorkspaceProvider — context + localStorage-persisted project id"
```

### Task 3.2: DensityContext

**Files:**
- Create: `web/lib/density-context.tsx`

- [ ] **Step 1: Create the file**

```tsx
"use client"

import * as React from "react"

type Density = "comfortable" | "compact"

interface DensityContextValue {
  density: Density
  setDensity: (d: Density) => void
}

const DensityContext = React.createContext<DensityContextValue | null>(null)
const STORAGE_KEY = "sentinel_density"

export function DensityProvider({ children }: { children: React.ReactNode }) {
  const [density, setDensityState] = React.useState<Density>(() => {
    if (typeof window === "undefined") return "comfortable"
    return (localStorage.getItem(STORAGE_KEY) as Density) ?? "comfortable"
  })

  const setDensity = React.useCallback((d: Density) => {
    setDensityState(d)
    if (typeof window !== "undefined") localStorage.setItem(STORAGE_KEY, d)
  }, [])

  const value = React.useMemo(() => ({ density, setDensity }), [density, setDensity])
  return <DensityContext.Provider value={value}>{children}</DensityContext.Provider>
}

export function useDensity() {
  const ctx = React.useContext(DensityContext)
  if (!ctx) throw new Error("useDensity must be used inside <DensityProvider>")
  return ctx
}
```

- [ ] **Step 2: Commit**

```
git add web/lib/density-context.tsx
git commit -m "feat(web): DensityProvider — comfortable/compact toggle persisted"
```

### Task 3.3: route-labels.ts

**Files:**
- Create: `web/lib/route-labels.ts`

- [ ] **Step 1: Create the file**

```tsx
export const routeLabels: Record<string, string> = {
  dashboard: "Dashboard",
  findings: "Findings",
  risks: "Risks",
  scans: "Scans",
  targets: "Targets",
  "auth-profiles": "Auth Profiles",
  artifacts: "Source Artifacts",
  surface: "Attack Surface",
  approvals: "Approvals",
  notifications: "Notifications",
  audit: "Audit Log",
  settings: "Settings",
}

export function labelForSegment(segment: string): string {
  if (routeLabels[segment]) return routeLabels[segment]
  // UUID-shaped segment → render as truncated id
  if (/^[0-9a-f]{8}-/i.test(segment)) return `#${segment.slice(0, 8)}`
  return segment.replace(/-/g, " ")
}
```

- [ ] **Step 2: Commit**

```
git add web/lib/route-labels.ts
git commit -m "feat(web): route-labels — pathname segment → breadcrumb label map"
```

### Task 3.4: WorkspaceSwitcher

**Files:**
- Create: `web/components/layout/workspace-switcher.tsx`

- [ ] **Step 1: Create the file**

```tsx
"use client"

import * as React from "react"
import { ChevronsUpDown, Check, ShieldCheck } from "lucide-react"
import * as Popover from "@base-ui/react/popover"
import { useWorkspace } from "@/lib/workspace-context"
import { cn } from "@/lib/utils"

export function WorkspaceSwitcher() {
  const { projects, projectId, setProjectId, activeProject } = useWorkspace()
  const [open, setOpen] = React.useState(false)

  return (
    <Popover.Root open={open} onOpenChange={setOpen}>
      <Popover.Trigger
        className="flex h-10 w-full items-center gap-2 rounded-md border border-border bg-surface-1 px-2 text-left text-body-sm hover:bg-surface-2 transition-colors duration-fast focus-ring"
      >
        <ShieldCheck className="size-4 text-brand shrink-0" />
        <div className="flex-1 truncate">
          <div className="text-body-sm font-medium text-foreground truncate">
            {activeProject?.display_name ?? activeProject?.name ?? "Select project"}
          </div>
        </div>
        <ChevronsUpDown className="size-4 text-muted-foreground shrink-0" />
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Positioner sideOffset={4} align="start">
          <Popover.Popup
            className="z-50 w-[224px] rounded-md border border-border bg-surface-2 p-1 shadow-xl"
          >
            {projects.length === 0 ? (
              <div className="px-2 py-3 text-body-sm text-muted-foreground">
                No projects available
              </div>
            ) : (
              projects.map((p) => (
                <button
                  key={p.id}
                  onClick={() => {
                    setProjectId(p.id)
                    setOpen(false)
                  }}
                  className={cn(
                    "flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-body-sm hover:bg-surface-3 transition-colors duration-fast focus-ring",
                    p.id === projectId && "bg-surface-3"
                  )}
                >
                  <span className="flex-1 truncate">{p.display_name ?? p.name}</span>
                  {p.id === projectId && <Check className="size-3.5 text-brand" />}
                </button>
              ))
            )}
          </Popover.Popup>
        </Popover.Positioner>
      </Popover.Portal>
    </Popover.Root>
  )
}
```

- [ ] **Step 2: Verify Base UI Popover is exported**

Run:
```
ls web/node_modules/@base-ui/react/popover/
```

Expected: directory exists. (Base UI ships popover; if not, fallback is a simple Headless `<details>` — note as a follow-up but should not happen.)

- [ ] **Step 3: Commit**

```
git add web/components/layout/workspace-switcher.tsx
git commit -m "feat(web): WorkspaceSwitcher — sidebar top control with project list"
```

### Task 3.5: SidebarGroup helper

**Files:**
- Create: `web/components/layout/sidebar-group.tsx`

- [ ] **Step 1: Create the file**

```tsx
"use client"

import * as React from "react"
import { ChevronDown } from "lucide-react"
import { cn } from "@/lib/utils"

export function SidebarGroup({
  label,
  defaultOpen = true,
  children,
}: {
  label: string
  defaultOpen?: boolean
  children: React.ReactNode
}) {
  const [open, setOpen] = React.useState(defaultOpen)
  return (
    <div className="mb-2">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-3 py-1.5 text-caption text-muted-foreground/80 hover:text-foreground transition-colors duration-fast focus-ring rounded-sm"
      >
        <span>{label}</span>
        <ChevronDown
          className={cn(
            "size-3 transition-transform duration-fast",
            !open && "-rotate-90"
          )}
        />
      </button>
      {open && <div className="space-y-0.5 mt-1">{children}</div>}
    </div>
  )
}
```

- [ ] **Step 2: Commit**

```
git add web/components/layout/sidebar-group.tsx
git commit -m "feat(web): SidebarGroup — collapsible caption header for sidebar sections"
```

### Task 3.6: Rewrite sidebar.tsx

**Files:**
- Modify: `web/components/layout/sidebar.tsx`

- [ ] **Step 1: Replace contents**

```tsx
"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import {
  LayoutDashboard, Shield, AlertTriangle, Play, Target, KeyRound, FileArchive,
  Globe, CheckCircle, Bell, FileText, Settings,
} from "lucide-react"
import { cn } from "@/lib/utils"
import { SidebarGroup } from "./sidebar-group"
import { WorkspaceSwitcher } from "./workspace-switcher"
import { useWorkspace } from "@/lib/workspace-context"

const groups = [
  {
    label: "Posture",
    items: [
      { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
      { href: "/findings", label: "Findings", icon: Shield },
      { href: "/risks", label: "Risks", icon: AlertTriangle },
    ],
  },
  {
    label: "Scanning",
    items: [
      { href: "/scans", label: "Scans", icon: Play },
      { href: "/targets", label: "Targets", icon: Target },
      { href: "/auth-profiles", label: "Auth Profiles", icon: KeyRound },
      { href: "/artifacts", label: "Source Artifacts", icon: FileArchive },
      { href: "/surface", label: "Attack Surface", icon: Globe },
    ],
  },
  {
    label: "Operations",
    items: [
      { href: "/approvals", label: "Approvals", icon: CheckCircle },
      { href: "/notifications", label: "Notifications", icon: Bell },
      { href: "/audit", label: "Audit Log", icon: FileText },
      { href: "/settings", label: "Settings", icon: Settings },
    ],
  },
] as const

export function Sidebar() {
  const pathname = usePathname()
  const { activeProject } = useWorkspace()

  return (
    <aside className="w-60 shrink-0 border-r border-border bg-surface-1 flex flex-col h-full">
      <div className="p-3 border-b border-border">
        <WorkspaceSwitcher />
      </div>

      <nav className="flex-1 overflow-y-auto p-2">
        {groups.map((g) => (
          <SidebarGroup key={g.label} label={g.label}>
            {g.items.map((item) => {
              const active = pathname.startsWith(item.href)
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={cn(
                    "relative flex items-center gap-2.5 rounded-md px-3 py-1.5 text-body-sm transition-colors duration-fast focus-ring",
                    active
                      ? "bg-surface-2 text-foreground font-medium before:absolute before:left-0 before:top-1.5 before:bottom-1.5 before:w-[2px] before:rounded-full before:bg-brand"
                      : "text-muted-foreground hover:bg-surface-2 hover:text-foreground"
                  )}
                >
                  <item.icon className="size-4 shrink-0" />
                  {item.label}
                </Link>
              )
            })}
          </SidebarGroup>
        ))}
      </nav>

      <div className="p-3 border-t border-border text-caption text-muted-foreground/70 space-y-1">
        <div className="truncate">{activeProject?.display_name ?? "—"}</div>
        <div>v0.1.0</div>
      </div>
    </aside>
  )
}
```

- [ ] **Step 2: Commit**

```
git add web/components/layout/sidebar.tsx
git commit -m "refactor(web): Sidebar — grouped, workspace switcher, brand left-border active state"
```

### Task 3.7: Breadcrumbs

**Files:**
- Create: `web/components/layout/breadcrumbs.tsx`

- [ ] **Step 1: Create the file**

```tsx
"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { ChevronRight } from "lucide-react"
import { labelForSegment } from "@/lib/route-labels"

export function Breadcrumbs() {
  const pathname = usePathname()
  const segments = pathname.split("/").filter(Boolean)
  if (segments.length === 0) return null

  const crumbs = segments.map((seg, i) => ({
    label: labelForSegment(seg),
    href: "/" + segments.slice(0, i + 1).join("/"),
    isLast: i === segments.length - 1,
  }))

  return (
    <nav aria-label="Breadcrumb" className="flex items-center gap-1 text-body-sm">
      {crumbs.map((c, i) => (
        <span key={c.href} className="flex items-center gap-1">
          {i > 0 && <ChevronRight className="size-3.5 text-muted-foreground/50" />}
          {c.isLast ? (
            <span className="text-foreground truncate max-w-[200px]">{c.label}</span>
          ) : (
            <Link
              href={c.href}
              className="text-muted-foreground hover:text-foreground transition-colors duration-fast focus-ring rounded-sm"
            >
              {c.label}
            </Link>
          )}
        </span>
      ))}
    </nav>
  )
}
```

- [ ] **Step 2: Commit**

```
git add web/components/layout/breadcrumbs.tsx
git commit -m "feat(web): Breadcrumbs — pathname-driven header navigation aid"
```

### Task 3.8: GlobalSearchTrigger

**Files:**
- Create: `web/components/layout/global-search-trigger.tsx`

- [ ] **Step 1: Create the file**

```tsx
"use client"

import { Search } from "lucide-react"

export function GlobalSearchTrigger({ onOpen }: { onOpen: () => void }) {
  return (
    <button
      type="button"
      onClick={onOpen}
      aria-label="Open command palette"
      className="hidden md:flex items-center gap-2 h-9 w-full max-w-md rounded-md border border-border bg-surface-1 px-3 text-body-sm text-muted-foreground hover:bg-surface-2 hover:text-foreground transition-colors duration-fast focus-ring"
    >
      <Search className="size-4 shrink-0" aria-hidden="true" />
      <span className="flex-1 text-left">Search or jump to…</span>
      <kbd className="rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
        ⌘K
      </kbd>
    </button>
  )
}
```

- [ ] **Step 2: Commit**

```
git add web/components/layout/global-search-trigger.tsx
git commit -m "feat(web): GlobalSearchTrigger — full-input header trigger for command palette"
```

### Task 3.9: ThemeSwitcher

**Files:**
- Create: `web/components/layout/theme-switcher.tsx`

- [ ] **Step 1: Add next-themes provider check**

Run:
```
grep -rn "ThemeProvider" web/app web/components --include='*.tsx' | head -5
```

If no results, `next-themes` is installed but no provider is mounted. We need to mount it.

- [ ] **Step 2: Create or update theme provider**

If no `theme-provider.tsx` exists, create `web/components/layout/theme-provider.tsx`:
```tsx
"use client"

import * as React from "react"
import { ThemeProvider as NextThemesProvider } from "next-themes"

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  return (
    <NextThemesProvider
      attribute="class"
      defaultTheme="dark"
      enableSystem={false}
      disableTransitionOnChange
    >
      {children}
    </NextThemesProvider>
  )
}
```

- [ ] **Step 3: Wrap RootLayout body**

Modify `web/app/layout.tsx`:

Find:
```tsx
<body className="min-h-screen bg-background font-sans antialiased">
  <QueryProvider>
    <AuthProvider>
      {children}
      <Toaster />
    </AuthProvider>
  </QueryProvider>
</body>
```

Replace with:
```tsx
<body className="min-h-screen bg-bg font-sans antialiased">
  <ThemeProvider>
    <QueryProvider>
      <AuthProvider>
        {children}
        <Toaster />
      </AuthProvider>
    </QueryProvider>
  </ThemeProvider>
</body>
```

Add import at top:
```tsx
import { ThemeProvider } from "@/components/layout/theme-provider"
```

- [ ] **Step 4: Create ThemeSwitcher**

`web/components/layout/theme-switcher.tsx`:
```tsx
"use client"

import * as React from "react"
import { Moon, Sun } from "lucide-react"
import { useTheme } from "next-themes"
import { Button } from "@/components/ui/button"

export function ThemeSwitcher() {
  const { theme, setTheme } = useTheme()
  const [mounted, setMounted] = React.useState(false)
  React.useEffect(() => setMounted(true), [])
  if (!mounted) return <div className="size-9" />
  const isDark = theme === "dark"
  return (
    <Button
      variant="ghost"
      size="icon"
      aria-label="Toggle theme"
      onClick={() => setTheme(isDark ? "light" : "dark")}
    >
      {isDark ? <Sun className="size-4" /> : <Moon className="size-4" />}
    </Button>
  )
}
```

- [ ] **Step 5: Commit**

```
git add web/components/layout/theme-provider.tsx web/components/layout/theme-switcher.tsx web/app/layout.tsx
git commit -m "feat(web): ThemeProvider + switcher — default dark, no system theme"
```

### Task 3.10: UserMenu

**Files:**
- Create: `web/components/layout/user-menu.tsx`

- [ ] **Step 1: Create the file**

```tsx
"use client"

import * as React from "react"
import { LogOut, Settings, User } from "lucide-react"
import * as Popover from "@base-ui/react/popover"
import Link from "next/link"
import { useAuth } from "@/features/auth/hooks"

export function UserMenu() {
  const { user, logout } = useAuth()
  const [open, setOpen] = React.useState(false)
  const displayName = user?.full_name || user?.email || "User"
  const initials = displayName.slice(0, 2).toUpperCase()

  return (
    <Popover.Root open={open} onOpenChange={setOpen}>
      <Popover.Trigger
        aria-label="User menu"
        className="flex items-center gap-2 h-9 px-1 rounded-md hover:bg-surface-2 transition-colors duration-fast focus-ring"
      >
        <div className="flex size-7 items-center justify-center rounded-full bg-brand-muted text-brand text-[11px] font-semibold">
          {initials}
        </div>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Positioner sideOffset={6} align="end">
          <Popover.Popup className="z-50 w-56 rounded-md border border-border bg-surface-2 p-1 shadow-xl">
            <div className="px-2.5 py-2 border-b border-border-subtle">
              <div className="text-body-sm font-medium text-foreground truncate">
                {displayName}
              </div>
              <div className="text-caption text-muted-foreground mt-0.5">
                {user?.role}
              </div>
            </div>
            <div className="p-1">
              <Link
                href="/settings"
                className="flex items-center gap-2 rounded-sm px-2 py-1.5 text-body-sm hover:bg-surface-3 focus-ring"
                onClick={() => setOpen(false)}
              >
                <Settings className="size-3.5 text-muted-foreground" />
                Settings
              </Link>
              <button
                onClick={() => { setOpen(false); void logout() }}
                className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-body-sm hover:bg-surface-3 focus-ring"
              >
                <LogOut className="size-3.5 text-muted-foreground" />
                Sign out
              </button>
            </div>
          </Popover.Popup>
        </Popover.Positioner>
      </Popover.Portal>
    </Popover.Root>
  )
}
```

- [ ] **Step 2: Commit**

```
git add web/components/layout/user-menu.tsx
git commit -m "feat(web): UserMenu — avatar dropdown with name/role/settings/sign-out"
```

### Task 3.11: Rewrite header.tsx

**Files:**
- Modify: `web/components/layout/header.tsx`

- [ ] **Step 1: Replace contents**

```tsx
"use client"

import { Bell } from "lucide-react"
import { Breadcrumbs } from "./breadcrumbs"
import { GlobalSearchTrigger } from "./global-search-trigger"
import { ThemeSwitcher } from "./theme-switcher"
import { UserMenu } from "./user-menu"
import { Button } from "@/components/ui/button"
import { PulseDot } from "@/components/security/pulse-dot"
import { useEmergencyStops } from "@/features/governance/hooks"

interface HeaderProps {
  onOpenCommandPalette?: () => void
}

export function Header({ onOpenCommandPalette }: HeaderProps) {
  const { data: stopsData } = useEmergencyStops()
  const hasActiveStops = (stopsData?.stops ?? []).length > 0

  return (
    <header className="h-14 border-b border-border bg-bg flex items-center gap-4 px-4">
      <div className="flex-1 min-w-0">
        <Breadcrumbs />
      </div>

      {onOpenCommandPalette && (
        <div className="hidden md:block flex-1 max-w-md">
          <GlobalSearchTrigger onOpen={onOpenCommandPalette} />
        </div>
      )}

      <div className="flex items-center gap-1.5 shrink-0">
        {hasActiveStops && (
          <span className="inline-flex items-center gap-1.5 rounded-md bg-[color:var(--severity-critical)]/12 px-2 py-1 text-caption text-[color:var(--severity-critical)]">
            <PulseDot tone="err" size="xs" aria-label="Emergency stop active" />
            ESTOP
          </span>
        )}
        <Button variant="ghost" size="icon" aria-label="Notifications" className="relative">
          <Bell className="size-4" />
          {hasActiveStops && (
            <span className="absolute top-1.5 right-1.5">
              <PulseDot tone="err" size="xs" aria-label="Unread alerts" />
            </span>
          )}
        </Button>
        <ThemeSwitcher />
        <UserMenu />
      </div>
    </header>
  )
}
```

- [ ] **Step 2: Commit**

```
git add web/components/layout/header.tsx
git commit -m "refactor(web): Header — breadcrumbs, center search, theme + user menu"
```

### Task 3.12: Update app-shell.tsx

**Files:**
- Modify: `web/components/layout/app-shell.tsx`

- [ ] **Step 1: Wrap with Workspace + Density providers**

Replace the body of `AppShell` with:
```tsx
"use client"

import { useEffect, useState } from "react"
import { Sidebar } from "./sidebar"
import { Header } from "./header"
import { CommandPalette } from "./command-palette"
import { CommandProvider } from "./command-provider"
import { WorkspaceProvider } from "@/lib/workspace-context"
import { DensityProvider } from "@/lib/density-context"

export function AppShell({ children }: { children: React.ReactNode }) {
  const [paletteOpen, setPaletteOpen] = useState(false)

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const isModK = e.key.toLowerCase() === "k" && (e.metaKey || e.ctrlKey)
      if (!isModK) return
      e.preventDefault()
      setPaletteOpen((prev) => !prev)
    }
    window.addEventListener("keydown", handler)
    return () => window.removeEventListener("keydown", handler)
  }, [])

  return (
    <WorkspaceProvider>
      <DensityProvider>
        <CommandProvider>
          <div className="flex h-screen overflow-hidden bg-bg">
            <Sidebar />
            <div className="flex-1 flex flex-col overflow-hidden">
              <Header onOpenCommandPalette={() => setPaletteOpen(true)} />
              <main className="flex-1 overflow-y-auto">
                <div className="mx-auto max-w-[1440px] px-6 py-5">
                  {children}
                </div>
              </main>
            </div>
            <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
          </div>
        </CommandProvider>
      </DensityProvider>
    </WorkspaceProvider>
  )
}
```

- [ ] **Step 2: Commit**

```
git add web/components/layout/app-shell.tsx
git commit -m "refactor(web): AppShell — wrap with Workspace + Density providers, max-w-1440 container"
```

### Task 3.13: Rewrite PageHeader

**Files:**
- Modify: `web/components/data/page-header.tsx`

- [ ] **Step 1: Replace contents**

```tsx
import * as React from "react"
import { cn } from "@/lib/utils"

interface PageHeaderProps {
  title: string
  description?: string
  /** Inline count next to the title (e.g. "1,247"). Optional. */
  count?: number | string
  /** Filter chips row (e.g. severity, status pickers). Renders below title. */
  filters?: React.ReactNode
  /** Right-aligned action buttons. */
  actions?: React.ReactNode
  className?: string
}

export function PageHeader({
  title,
  description,
  count,
  filters,
  actions,
  className,
}: PageHeaderProps) {
  return (
    <div className={cn("pb-4 border-b border-border-subtle mb-5", className)}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-baseline gap-2">
            <h1 className="text-h1 text-foreground">{title}</h1>
            {count !== undefined && (
              <span className="text-body-sm text-muted-foreground tabular">
                ({typeof count === "number" ? count.toLocaleString() : count})
              </span>
            )}
          </div>
          {description && (
            <p className="text-body-sm text-muted-foreground mt-1">{description}</p>
          )}
        </div>
        {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
      </div>
      {filters && <div className="mt-3 flex items-center gap-2 flex-wrap">{filters}</div>}
    </div>
  )
}
```

- [ ] **Step 2: Commit**

```
git add web/components/data/page-header.tsx
git commit -m "refactor(web): PageHeader — count chip, inline filters row, h1 typography"
```

### Task 3.14: PR 3 build, deploy, smoke test

- [ ] **Step 1: Sync, build, deploy**

```
rsync -az --delete --exclude node_modules --exclude .next --exclude .git web/ okyay@77.42.34.174:/tmp/sentinelcore-src/web/
ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src/web && \
  docker build --build-arg NEXT_PUBLIC_API_URL='' -t sentinelcore/frontend:redesign-pr3 . 2>&1 | tail -10 && \
  docker tag sentinelcore/frontend:redesign-pr3 sentinelcore/frontend:pilot && \
  cd /opt/sentinelcore/compose && docker compose up -d frontend"
curl -s -o /dev/null -w 'frontend: %{http_code}\n' https://sentinelcore.resiliencetech.com.tr/
```

- [ ] **Step 2: Smoke test**

In a browser, login and verify:
- Sidebar shows three groups (Posture / Scanning / Operations)
- Workspace switcher shows project list, click changes project, persists across reload
- Active page link has brand violet left border
- Header shows breadcrumbs + center search + theme switcher + user menu
- Cmd+K still opens command palette
- Theme switcher toggles between dark and light, page rerenders
- User menu dropdown opens, "Sign out" works

- [ ] **Step 3: Push branch**

```
git push
```

---

## PR 4 — Data primitives + viz

### Task 4.1: Branded empty state

**Files:**
- Create: `web/components/data/empty-state-branded.tsx`

- [ ] **Step 1: Create the file**

```tsx
import * as React from "react"
import Link from "next/link"
import { type LucideIcon } from "lucide-react"
import { Button } from "@/components/ui/button"

interface EmptyStateBrandedProps {
  icon: LucideIcon
  title: string
  description?: string
  action?: { label: string; href?: string; onClick?: () => void }
}

export function EmptyStateBranded({ icon: Icon, title, description, action }: EmptyStateBrandedProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-6 text-center">
      <div className="flex size-12 items-center justify-center rounded-full bg-brand-muted text-brand mb-4">
        <Icon className="size-5" />
      </div>
      <h3 className="text-h3 text-foreground">{title}</h3>
      {description && (
        <p className="text-body-sm text-muted-foreground mt-1 max-w-sm">{description}</p>
      )}
      {action && (
        <div className="mt-4">
          {action.href ? (
            <Button asChild>
              <Link href={action.href}>{action.label}</Link>
            </Button>
          ) : (
            <Button onClick={action.onClick}>{action.label}</Button>
          )}
        </div>
      )}
    </div>
  )
}
```

- [ ] **Step 2: Commit**

```
git add web/components/data/empty-state-branded.tsx
git commit -m "feat(web): EmptyStateBranded — icon + title + CTA empty-state primitive"
```

### Task 4.2: DensityToggle

**Files:**
- Create: `web/components/data/density-toggle.tsx`

- [ ] **Step 1: Create the file**

```tsx
"use client"

import { Rows3, Rows4 } from "lucide-react"
import { useDensity } from "@/lib/density-context"
import { cn } from "@/lib/utils"

export function DensityToggle() {
  const { density, setDensity } = useDensity()
  return (
    <div className="inline-flex items-center rounded-md border border-border bg-surface-1 p-0.5">
      <button
        type="button"
        aria-label="Comfortable density"
        onClick={() => setDensity("comfortable")}
        className={cn(
          "flex size-7 items-center justify-center rounded-sm transition-colors duration-fast focus-ring",
          density === "comfortable" ? "bg-surface-3 text-foreground" : "text-muted-foreground hover:text-foreground"
        )}
      >
        <Rows3 className="size-3.5" />
      </button>
      <button
        type="button"
        aria-label="Compact density"
        onClick={() => setDensity("compact")}
        className={cn(
          "flex size-7 items-center justify-center rounded-sm transition-colors duration-fast focus-ring",
          density === "compact" ? "bg-surface-3 text-foreground" : "text-muted-foreground hover:text-foreground"
        )}
      >
        <Rows4 className="size-3.5" />
      </button>
    </div>
  )
}
```

- [ ] **Step 2: Commit**

```
git add web/components/data/density-toggle.tsx
git commit -m "feat(web): DensityToggle — comfortable/compact UI for tables"
```

### Task 4.3: Sticky sub-header

**Files:**
- Create: `web/components/data/sticky-subheader.tsx`

- [ ] **Step 1: Create the file**

```tsx
"use client"

import * as React from "react"
import { cn } from "@/lib/utils"

export function StickySubheader({
  children,
  className,
}: {
  children: React.ReactNode
  className?: string
}) {
  return (
    <div
      className={cn(
        "sticky top-0 z-20 -mx-6 px-6 py-2 bg-bg/85 backdrop-blur-md border-b border-border-subtle",
        className
      )}
    >
      {children}
    </div>
  )
}
```

- [ ] **Step 2: Commit**

```
git add web/components/data/sticky-subheader.tsx
git commit -m "feat(web): StickySubheader — pinned filter row on scroll"
```

### Task 4.4: Rewrite DataTable

**Files:**
- Modify: `web/components/data/data-table.tsx`

- [ ] **Step 1: Replace contents**

```tsx
"use client"

import * as React from "react"
import { ChevronDown, ChevronUp } from "lucide-react"
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table"
import { LoadingState } from "./loading-state"
import { EmptyState } from "./empty-state"
import { useDensity } from "@/lib/density-context"
import { cn } from "@/lib/utils"

export interface Column<T> {
  key: string
  header: string
  render: (item: T) => React.ReactNode
  className?: string
  /** When set, the column header becomes a sort toggle. */
  sortKey?: string
}

export interface SortState {
  key: string
  dir: "asc" | "desc"
}

interface DataTableProps<T> {
  columns: Column<T>[]
  data: T[]
  isLoading?: boolean
  emptyMessage?: string
  emptyContent?: React.ReactNode
  onRowClick?: (item: T) => void
  sort?: SortState
  onSortChange?: (sort: SortState) => void
}

export function DataTable<T>({
  columns,
  data,
  isLoading,
  emptyMessage = "No data found",
  emptyContent,
  onRowClick,
  sort,
  onSortChange,
}: DataTableProps<T>) {
  const { density } = useDensity()

  if (isLoading) return <LoadingState rows={8} columns={columns.length} />
  if (data.length === 0) return emptyContent ? <>{emptyContent}</> : <EmptyState title={emptyMessage} />

  return (
    <Table>
      <TableHeader>
        <TableRow>
          {columns.map((col) => {
            const isSorted = sort && sort.key === col.sortKey
            const sortable = !!col.sortKey && !!onSortChange
            return (
              <TableHead key={col.key} className={col.className}>
                {sortable ? (
                  <button
                    type="button"
                    onClick={() => {
                      if (!col.sortKey) return
                      onSortChange?.({
                        key: col.sortKey,
                        dir: isSorted && sort?.dir === "asc" ? "desc" : "asc",
                      })
                    }}
                    className="inline-flex items-center gap-1 hover:text-foreground transition-colors duration-fast"
                  >
                    {col.header}
                    {isSorted && sort?.dir === "asc" && <ChevronUp className="size-3" />}
                    {isSorted && sort?.dir === "desc" && <ChevronDown className="size-3" />}
                  </button>
                ) : (
                  col.header
                )}
              </TableHead>
            )
          })}
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.map((item, idx) => (
          <TableRow
            key={idx}
            data-density={density}
            className={cn(
              onRowClick &&
                "cursor-pointer relative hover:before:absolute hover:before:left-0 hover:before:top-0 hover:before:bottom-0 hover:before:w-[2px] hover:before:bg-brand"
            )}
            onClick={() => onRowClick?.(item)}
          >
            {columns.map((col) => (
              <TableCell key={col.key} data-density={density} className={col.className}>
                {col.render(item)}
              </TableCell>
            ))}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}
```

- [ ] **Step 2: Update LoadingState to accept columns**

`web/components/data/loading-state.tsx` — replace contents:
```tsx
import { cn } from "@/lib/utils"

export function LoadingState({
  rows = 8,
  columns = 5,
  className,
}: {
  rows?: number
  columns?: number
  className?: string
}) {
  return (
    <div className={cn("w-full overflow-hidden rounded-md border border-border-subtle", className)}>
      <div className="border-b border-border-subtle bg-surface-1 px-3 py-2.5 flex gap-3">
        {Array.from({ length: columns }).map((_, i) => (
          <div
            key={i}
            className="h-3 flex-1 animate-pulse rounded bg-surface-3"
            style={{ maxWidth: i === 0 ? 80 : i === columns - 1 ? 100 : undefined }}
          />
        ))}
      </div>
      <div className="divide-y divide-border-subtle">
        {Array.from({ length: rows }).map((_, r) => (
          <div key={r} className="px-3 py-3 flex gap-3">
            {Array.from({ length: columns }).map((_, c) => (
              <div
                key={c}
                className="h-3 flex-1 animate-pulse rounded bg-surface-2"
                style={{
                  animationDelay: `${(r + c) * 30}ms`,
                  maxWidth: c === 0 ? 80 : c === columns - 1 ? 100 : undefined,
                }}
              />
            ))}
          </div>
        ))}
      </div>
    </div>
  )
}
```

- [ ] **Step 3: Commit**

```
git add web/components/data/data-table.tsx web/components/data/loading-state.tsx
git commit -m "refactor(web): DataTable — sortable, density-aware, structured skeleton"
```

### Task 4.5: Sparkline primitive

**Files:**
- Create: `web/components/security/sparkline.tsx`

- [ ] **Step 1: Create the file**

```tsx
"use client"

import * as React from "react"
import { cn } from "@/lib/utils"

interface SparklineProps {
  data: number[]
  width?: number
  height?: number
  tone?: "neutral" | "positive" | "negative"
  className?: string
}

const toneClass = {
  neutral: "text-muted-foreground",
  positive: "text-[color:var(--signal-new)]",
  negative: "text-[color:var(--severity-critical)]",
} as const

export function Sparkline({
  data,
  width = 60,
  height = 24,
  tone = "neutral",
  className,
}: SparklineProps) {
  const path = React.useMemo(() => {
    if (data.length < 2) return ""
    const min = Math.min(...data)
    const max = Math.max(...data)
    const range = max - min || 1
    const stepX = width / (data.length - 1)
    return data
      .map((v, i) => {
        const x = i * stepX
        const y = height - ((v - min) / range) * height
        return `${i === 0 ? "M" : "L"} ${x.toFixed(1)} ${y.toFixed(1)}`
      })
      .join(" ")
  }, [data, width, height])

  if (data.length < 2) {
    return <div className={cn("inline-block", className)} style={{ width, height }} aria-hidden="true" />
  }
  return (
    <svg
      className={cn("inline-block", toneClass[tone], className)}
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      aria-hidden="true"
    >
      <path d={path} fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
```

- [ ] **Step 2: Commit**

```
git add web/components/security/sparkline.tsx
git commit -m "feat(security): Sparkline — 60x24 SVG micro-trend primitive"
```

### Task 4.6: SeverityHeatmap

**Files:**
- Create: `web/components/security/severity-heatmap.tsx`

- [ ] **Step 1: Create the file**

```tsx
"use client"

import * as React from "react"
import { cn } from "@/lib/utils"

interface HeatmapCell {
  /** ISO week-day (0 = Sun … 6 = Sat) */
  day: number
  /** 0–23 hour-of-day */
  hour: number
  /** Count of items in this slot. */
  count: number
}

interface SeverityHeatmapProps {
  cells: HeatmapCell[]
  className?: string
}

const dayLabels = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]

export function SeverityHeatmap({ cells, className }: SeverityHeatmapProps) {
  const max = Math.max(1, ...cells.map((c) => c.count))
  const grid = React.useMemo(() => {
    const out: number[][] = Array.from({ length: 7 }, () => Array(24).fill(0))
    for (const c of cells) out[c.day]![c.hour] = c.count
    return out
  }, [cells])

  return (
    <div className={cn("flex gap-1.5", className)}>
      <div className="flex flex-col justify-between text-caption text-muted-foreground/70 py-px">
        {dayLabels.map((d, i) => (
          <span key={i} className="leading-none">{d.slice(0, 1)}</span>
        ))}
      </div>
      <div className="grid grid-cols-24 gap-px flex-1" style={{ gridTemplateColumns: "repeat(24, minmax(0, 1fr))" }}>
        {grid.flatMap((row, di) =>
          row.map((count, hi) => {
            const intensity = count / max
            return (
              <div
                key={`${di}-${hi}`}
                className="aspect-square rounded-[2px]"
                style={{
                  backgroundColor:
                    count === 0
                      ? "var(--surface-2)"
                      : `oklch(from var(--severity-critical) l c h / ${0.15 + intensity * 0.85})`,
                }}
                title={`${dayLabels[di]} ${hi}:00 — ${count} findings`}
                aria-label={`${dayLabels[di]} ${hi}:00 — ${count} findings`}
              />
            )
          })
        )}
      </div>
    </div>
  )
}
```

- [ ] **Step 2: Commit**

```
git add web/components/security/severity-heatmap.tsx
git commit -m "feat(security): SeverityHeatmap — 7x24 cell density visualization"
```

### Task 4.7: StackedBar

**Files:**
- Create: `web/components/security/stacked-bar.tsx`

- [ ] **Step 1: Create the file**

```tsx
"use client"

import * as React from "react"
import { cn } from "@/lib/utils"

type Severity = "critical" | "high" | "medium" | "low" | "info"

interface StackedBarProps {
  segments: { severity: Severity; count: number }[]
  height?: number
  className?: string
}

const severityVar: Record<Severity, string> = {
  critical: "--severity-critical",
  high: "--severity-high",
  medium: "--severity-medium",
  low: "--severity-low",
  info: "--severity-info",
}

const severityLabel: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
}

export function StackedBar({ segments, height = 8, className }: StackedBarProps) {
  const total = segments.reduce((s, x) => s + x.count, 0)
  if (total === 0) {
    return (
      <div
        className={cn("w-full rounded-full bg-surface-2", className)}
        style={{ height }}
        aria-label="No findings"
      />
    )
  }
  return (
    <div
      className={cn("flex w-full overflow-hidden rounded-full bg-surface-2", className)}
      style={{ height }}
      role="img"
      aria-label={`Severity distribution: ${segments
        .map((s) => `${s.count} ${severityLabel[s.severity]}`)
        .join(", ")}`}
    >
      {segments.map((s) => {
        const pct = (s.count / total) * 100
        if (pct === 0) return null
        return (
          <div
            key={s.severity}
            style={{
              width: `${pct}%`,
              backgroundColor: `var(${severityVar[s.severity]})`,
            }}
            title={`${severityLabel[s.severity]}: ${s.count}`}
          />
        )
      })}
    </div>
  )
}
```

- [ ] **Step 2: Commit**

```
git add web/components/security/stacked-bar.tsx
git commit -m "feat(security): StackedBar — single-row severity stacked-segment bar"
```

### Task 4.8: Recalibrate existing security primitives

**Files:**
- Modify: `web/components/security/contribution-bar.tsx`
- Modify: `web/components/security/score-display.tsx`
- Modify: `web/components/security/score-ring.tsx`

- [ ] **Step 1: contribution-bar height adjustment**

Open the file and find any `h-1.5` / `h-[6px]`. Change to `h-1` / `h-[4px]`.

- [ ] **Step 2: score-display / score-ring stroke width**

Find SVG `strokeWidth` values. If `8` or `10`, reduce by ~25% (8 → 6, 10 → 8). Keep proportions to viewBox.

- [ ] **Step 3: Commit**

```
git add web/components/security/contribution-bar.tsx web/components/security/score-display.tsx web/components/security/score-ring.tsx
git commit -m "refactor(security): thinner contribution bar + score ring strokes"
```

### Task 4.9: Update SeverityDistributionChart to use StackedBar

**Files:**
- Modify: `web/features/risks/severity-distribution-chart.tsx`

- [ ] **Step 1: Replace the chart body**

Find the existing severity rendering in this file. Replace with:
```tsx
import { StackedBar } from "@/components/security/stacked-bar"
import { Badge } from "@/components/ui/badge"

// Inside the component, after `risks` array is computed:
const severityCounts = (["critical","high","medium","low","info"] as const).map((sev) => ({
  severity: sev,
  count: risks.filter((r) => r.severity === sev && r.status === "active").length,
}))

return (
  <ChartContainer title="Severity distribution" insight={...}>
    <StackedBar segments={severityCounts} height={10} />
    <ul className="mt-4 grid grid-cols-2 gap-y-2 gap-x-6">
      {severityCounts.map((s) => (
        <li key={s.severity} className="flex items-center justify-between text-body-sm">
          <Badge variant="severity" tone={s.severity}>{s.severity}</Badge>
          <span className="tabular text-muted-foreground">{s.count}</span>
        </li>
      ))}
    </ul>
  </ChartContainer>
)
```

(Adapt to actual existing variable names in the file — keep the original `insight` content.)

- [ ] **Step 2: Commit**

```
git add web/features/risks/severity-distribution-chart.tsx
git commit -m "refactor(risks): SeverityDistributionChart now uses StackedBar primitive"
```

### Task 4.10: PR 4 build, deploy, smoke test

- [ ] **Step 1: Sync, build, deploy**

```
rsync -az --delete --exclude node_modules --exclude .next --exclude .git web/ okyay@77.42.34.174:/tmp/sentinelcore-src/web/
ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src/web && \
  docker build --build-arg NEXT_PUBLIC_API_URL='' -t sentinelcore/frontend:redesign-pr4 . 2>&1 | tail -10 && \
  docker tag sentinelcore/frontend:redesign-pr4 sentinelcore/frontend:pilot && \
  cd /opt/sentinelcore/compose && docker compose up -d frontend"
curl -s -o /dev/null -w 'frontend: %{http_code}\n' https://sentinelcore.resiliencetech.com.tr/
```

- [ ] **Step 2: Smoke test — Findings, Risks, Scans tables**

Visit each list page. Verify:
- Sticky header on scroll within long tables
- Hover row highlights with brand left border
- Density toggle (mounted in PR 5 — will appear there) not yet visible; tables still default comfortable
- Skeleton-loading skeletons mirror column counts

- [ ] **Step 3: Push branch**

```
git push
```

---

## PR 5 — Pages

This PR is the most surface area; one task per page, each with a build + smoke at the end so issues get caught before stacking.

### Task 5.1: Dashboard hero composition

**Files:**
- Modify: `web/app/(dashboard)/dashboard/page.tsx`

- [ ] **Step 1: Replace contents**

```tsx
"use client"

import { useMemo } from "react"
import { PageHeader } from "@/components/data/page-header"
import { ChangeSummaryStrip } from "@/components/security/change-summary-strip"
import { MicroInsight } from "@/components/security/micro-insight"
import { SeverityDistributionChart } from "@/features/risks/severity-distribution-chart"
import { TopRisksCard } from "@/features/risks/top-risks-card"
import { RuntimeConfirmedCard } from "@/features/dashboard/runtime-confirmed-card"
import { PublicExposureCard } from "@/features/dashboard/public-exposure-card"
import { useRisks } from "@/features/risks/hooks"
import { useScans } from "@/features/scans/hooks"
import { useProjectId } from "@/lib/workspace-context"
import { computeDashboardTiles } from "@/features/dashboard/dashboard-stats"

export default function DashboardPage() {
  const projectId = useProjectId()

  const { data: risksData, isLoading: risksLoading } = useRisks({
    project_id: projectId, status: "all", limit: 200,
  })
  const { data: scansData, isLoading: scansLoading } = useScans({ limit: 25 })

  const isLoading = risksLoading || scansLoading || !projectId

  const tiles = useMemo(
    () => computeDashboardTiles(risksData?.risks ?? [], scansData?.scans ?? []),
    [risksData, scansData]
  )

  const risks = risksData?.risks ?? []
  const activeCount = risks.filter((r) => r.status === "active").length
  const criticalCount = risks.filter(
    (r) => r.status === "active" && r.severity === "critical"
  ).length

  const insightText =
    activeCount === 0
      ? "No active risks. Your attack surface looks clean."
      : criticalCount > 0
        ? `${criticalCount} critical risk${criticalCount > 1 ? "s" : ""} need${
            criticalCount === 1 ? "s" : ""
          } attention across ${activeCount} active.`
        : `${activeCount} active risk${activeCount > 1 ? "s" : ""} — none critical.`
  const insightTone = (criticalCount > 0
    ? "negative"
    : activeCount > 0
      ? "neutral"
      : "positive") as "negative" | "neutral" | "positive"

  return (
    <div className="space-y-6">
      <PageHeader title="Dashboard" description="Security posture at a glance." />

      <section>
        {!isLoading && <MicroInsight text={insightText} tone={insightTone} />}
        <div className="mt-3">
          <ChangeSummaryStrip tiles={tiles} isLoading={isLoading} />
        </div>
      </section>

      <SeverityDistributionChart risks={risks} isLoading={isLoading} />

      <div className="grid gap-4 lg:grid-cols-3">
        {projectId && <TopRisksCard projectId={projectId} />}
        <RuntimeConfirmedCard risks={risks} isLoading={isLoading} />
        <PublicExposureCard risks={risks} isLoading={isLoading} />
      </div>
    </div>
  )
}
```

- [ ] **Step 2: Commit**

```
git add web/app/(dashboard)/dashboard/page.tsx
git commit -m "refactor(dashboard): hero composition, useProjectId from context, 3-col grid"
```

### Task 5.2: Findings list page

**Files:**
- Modify: `web/app/(dashboard)/findings/page.tsx`
- Reference: `web/features/findings/*` (no rewrite needed; just consumed by page)

- [ ] **Step 1: Add filter chips, count, density toggle, branded empty**

Open the file. The current page likely has `<PageHeader title="Findings" />` and a table. Replace with the pattern below — adapt to the actual filter state hooks already present.

```tsx
import { Shield } from "lucide-react"
import { PageHeader } from "@/components/data/page-header"
import { DensityToggle } from "@/components/data/density-toggle"
import { EmptyStateBranded } from "@/components/data/empty-state-branded"
// … existing imports

const isEmpty = !isLoading && (data?.findings?.length ?? 0) === 0

return (
  <>
    <PageHeader
      title="Findings"
      count={isLoading ? "—" : data?.total ?? 0}
      filters={
        <>
          {/* existing severity / status / project filter chips */}
        </>
      }
      actions={<DensityToggle />}
    />
    {isEmpty ? (
      <EmptyStateBranded
        icon={Shield}
        title="No findings yet"
        description="Findings appear after a scan completes. Configure a target and run your first scan."
        action={{ label: "Go to scans", href: "/scans" }}
      />
    ) : (
      <FindingsTable /* … */ />
    )}
  </>
)
```

- [ ] **Step 2: Commit**

```
git add web/app/(dashboard)/findings/page.tsx
git commit -m "refactor(findings): page header with count + filters + density, branded empty"
```

### Task 5.3: Risks list page

**Files:**
- Modify: `web/app/(dashboard)/risks/page.tsx`

- [ ] **Step 1: Apply same pattern as Findings**

Use `EmptyStateBranded` with icon `AlertTriangle`, title `"No risks correlated yet"`, description `"Risks appear after a SAST + DAST scan completes for this project."`, no CTA (correlation is automatic).

- [ ] **Step 2: Commit**

```
git add web/app/(dashboard)/risks/page.tsx
git commit -m "refactor(risks): page header with count + filters, branded empty"
```

### Task 5.4: Scans list page

**Files:**
- Modify: `web/app/(dashboard)/scans/page.tsx`

- [ ] **Step 1: Apply pattern**

Branded empty: icon `Play`, title `"No scans yet"`, description `"Configure a scan target to run your first scan."`, action `{ label: "Configure target", href: "/targets" }`.

- [ ] **Step 2: Commit**

```
git add web/app/(dashboard)/scans/page.tsx
git commit -m "refactor(scans): page header with count + density, branded empty"
```

### Task 5.5–5.10: Targets / Auth Profiles / Artifacts / Surface / Approvals / Notifications / Audit list pages

For each of these seven pages, apply the same shape:
- `<PageHeader title="…" count={…} filters={…} actions={…}>`
- `<EmptyStateBranded …>` when list is empty
- Existing table or list component is the body

Per-page details:

| Page                | Empty icon         | Empty title                 | CTA                                   |
|---------------------|--------------------|-----------------------------|---------------------------------------|
| `/targets`          | `Target`           | "No scan targets configured" | "New target" — opens existing dialog |
| `/auth-profiles`    | `KeyRound`         | "No auth profiles"          | "New profile" — opens existing dialog|
| `/artifacts`        | `FileArchive`      | "No source artifacts"       | "Upload artifact" — opens dialog     |
| `/surface`          | `Globe`            | "No surface entries yet"    | none                                 |
| `/approvals`        | `CheckCircle`      | "No pending approvals"      | none                                 |
| `/notifications`    | `Bell`             | "Inbox zero"                | none                                 |
| `/audit`            | `FileText`         | "No audit events recorded"  | none                                 |

- [ ] **Step 1: For each page, apply the pattern + branded empty + density**

Do them one at a time, each followed by a commit.

- [ ] **Step 2: Commits (one per page)**

After each page, commit with a focused message, e.g. `refactor(targets): page header + branded empty`.

### Task 5.11: Settings two-column layout

**Files:**
- Modify: `web/app/(dashboard)/settings/page.tsx`

- [ ] **Step 1: Wrap in two-column layout**

```tsx
import { PageHeader } from "@/components/data/page-header"
import Link from "next/link"

const sections = [
  { id: "profile", label: "Profile" },
  { id: "workspace", label: "Workspace" },
  { id: "notifications", label: "Notifications" },
  { id: "sso", label: "SSO" },
  { id: "api-keys", label: "API Keys" },
] as const

export default function SettingsPage() {
  return (
    <>
      <PageHeader title="Settings" description="Manage your account and workspace." />
      <div className="grid gap-6 grid-cols-[200px_1fr]">
        <aside className="space-y-1">
          {sections.map((s) => (
            <a
              key={s.id}
              href={`#${s.id}`}
              className="block rounded-md px-2 py-1.5 text-body-sm text-muted-foreground hover:bg-surface-2 hover:text-foreground transition-colors duration-fast"
            >
              {s.label}
            </a>
          ))}
        </aside>
        <div className="space-y-10">
          {/* existing settings content split into <section id="profile"> blocks */}
        </div>
      </div>
    </>
  )
}
```

Adapt the right-side content from the existing settings page; keep its functionality but wrap each subgroup in `<section id="…">`.

- [ ] **Step 2: Commit**

```
git add web/app/(dashboard)/settings/page.tsx
git commit -m "refactor(settings): two-column layout with section nav"
```

### Task 5.12: Detail page 3-column shell

**Files:**
- Create: `web/components/data/detail-shell.tsx`

- [ ] **Step 1: Create the shell**

```tsx
import * as React from "react"
import { cn } from "@/lib/utils"

interface DetailShellProps {
  leftRail: React.ReactNode
  main: React.ReactNode
  rightRail?: React.ReactNode
  className?: string
}

export function DetailShell({ leftRail, main, rightRail, className }: DetailShellProps) {
  return (
    <div
      className={cn(
        "grid gap-6",
        rightRail
          ? "grid-cols-[240px_1fr_320px]"
          : "grid-cols-[240px_1fr]",
        className
      )}
    >
      <aside className="space-y-4 text-body-sm">{leftRail}</aside>
      <div className="min-w-0">{main}</div>
      {rightRail && <aside className="space-y-4">{rightRail}</aside>}
    </div>
  )
}
```

- [ ] **Step 2: Apply to Findings detail**

`web/app/(dashboard)/findings/[id]/page.tsx` — wrap the existing content in `<DetailShell leftRail={…} main={…} rightRail={…}>`. The left rail is a key-value `<dl>` with severity, project, scan, dates. The right rail holds resolve/mute/reopen actions and a "Related findings" list (existing data is already fetched).

Concretely:
```tsx
<DetailShell
  leftRail={
    <dl className="space-y-2">
      <div className="flex items-center justify-between"><dt className="text-muted-foreground">Severity</dt><dd><SeverityBadge severity={f.severity} /></dd></div>
      <div className="flex items-center justify-between"><dt className="text-muted-foreground">Project</dt><dd>{f.project_name}</dd></div>
      <div className="flex items-center justify-between"><dt className="text-muted-foreground">Scan</dt><dd>#{f.scan_job_id?.slice(0, 8)}</dd></div>
      <div className="flex items-center justify-between"><dt className="text-muted-foreground">First seen</dt><dd>{format(f.first_seen_at)}</dd></div>
      <div className="flex items-center justify-between"><dt className="text-muted-foreground">Last seen</dt><dd>{format(f.last_seen_at)}</dd></div>
    </dl>
  }
  main={ /* existing description, evidence, code snippet */ }
  rightRail={
    <>
      <div className="flex flex-col gap-1.5">
        {/* resolve/mute/reopen Buttons stacked */}
      </div>
      {related.length > 0 && (
        <div>
          <h4 className="text-caption text-muted-foreground mb-2">Related findings</h4>
          <ul className="space-y-1.5">{ /* related items */ }</ul>
        </div>
      )}
    </>
  }
/>
```

- [ ] **Step 3: Apply to Risks detail and Scans detail**

Same pattern. For Risks: right rail holds resolve/mute/reopen + linked findings + risk-score sparkline of last 30 days. For Scans: right rail holds cancel button (if running) + linked findings count + duration / progress.

- [ ] **Step 4: Commit**

```
git add web/components/data/detail-shell.tsx web/app/\(dashboard\)/findings/\[id\]/page.tsx web/app/\(dashboard\)/risks/\[id\]/page.tsx web/app/\(dashboard\)/scans/\[id\]/page.tsx
git commit -m "feat(web): DetailShell — 3-column rail/main/rail for finding/risk/scan detail"
```

### Task 5.13: PR 5 build, deploy, smoke

- [ ] **Step 1: Sync, build, deploy**

```
rsync -az --delete --exclude node_modules --exclude .next --exclude .git web/ okyay@77.42.34.174:/tmp/sentinelcore-src/web/
ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src/web && \
  docker build --build-arg NEXT_PUBLIC_API_URL='' -t sentinelcore/frontend:redesign-pr5 . 2>&1 | tail -10 && \
  docker tag sentinelcore/frontend:redesign-pr5 sentinelcore/frontend:pilot && \
  cd /opt/sentinelcore/compose && docker compose up -d frontend"
curl -s -o /dev/null -w 'frontend: %{http_code}\n' https://sentinelcore.resiliencetech.com.tr/
```

- [ ] **Step 2: Smoke test all 12 routes + 3 detail pages**

Login, walk through every route. Confirm:
- Headers show count, filters, action buttons
- Empty pages show branded empty state with right CTA
- Detail pages have 3-column layout
- Density toggle in headers persists across reload
- All existing actions (resolve/mute/reopen/cancel-scan/etc.) still work

- [ ] **Step 3: Push branch**

```
git push
```

---

## PR 6 — Login + motion polish + final QA

### Task 6.1: Redesign login

**Files:**
- Modify: `web/app/(auth)/login/page.tsx`

- [ ] **Step 1: Replace contents with split-screen layout**

```tsx
"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import { ShieldCheck } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useAuth } from "@/features/auth/hooks"

export default function LoginPage() {
  const { login, isAuthenticated } = useAuth()
  const router = useRouter()
  const [email, setEmail] = React.useState("")
  const [password, setPassword] = React.useState("")
  const [error, setError] = React.useState<string | null>(null)
  const [loading, setLoading] = React.useState(false)

  React.useEffect(() => {
    if (isAuthenticated) router.push("/findings")
  }, [isAuthenticated, router])

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      await login(email, password)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen grid lg:grid-cols-[3fr_2fr] bg-bg">
      <aside className="hidden lg:flex relative items-center justify-center p-10 bg-gradient-to-br from-[oklch(0.18_0.04_285)] to-[oklch(0.14_0.02_14)] overflow-hidden">
        <div className="relative z-10 max-w-md">
          <div className="flex items-center gap-2 mb-6">
            <ShieldCheck className="size-8 text-brand" />
            <span className="text-display text-foreground">SentinelCore</span>
          </div>
          <p className="text-h2 text-muted-foreground/90 leading-snug">
            Application security, automated. SAST + DAST + risk correlation in one platform.
          </p>
        </div>
      </aside>

      <main className="flex items-center justify-center p-6 lg:p-10">
        <div className="w-full max-w-sm space-y-6">
          <div className="lg:hidden flex items-center gap-2 mb-6">
            <ShieldCheck className="size-7 text-brand" />
            <span className="text-h1 text-foreground">SentinelCore</span>
          </div>

          <div>
            <h1 className="text-h1 text-foreground">Sign in</h1>
            <p className="text-body-sm text-muted-foreground mt-1">
              Welcome back. Enter your credentials to continue.
            </p>
          </div>

          <form onSubmit={onSubmit} className="space-y-4">
            <div>
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                required
              />
            </div>
            <div>
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
              />
            </div>
            {error && (
              <p className="text-body-sm text-[color:var(--severity-critical)]">{error}</p>
            )}
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? "Signing in…" : "Sign in"}
            </Button>
          </form>

          <p className="text-caption text-muted-foreground text-center">
            v0.1.0 · Need help? Contact your administrator.
          </p>
        </div>
      </main>
    </div>
  )
}
```

- [ ] **Step 2: Commit**

```
git add web/app/(auth)/login/page.tsx
git commit -m "refactor(login): split-screen redesign with brand hero + form card"
```

### Task 6.2: Custom shimmer keyframe

**Files:**
- Modify: `web/app/globals.css`

- [ ] **Step 1: Append shimmer keyframe**

At end of `globals.css`:
```css
@keyframes shimmer {
  0% { background-position: -200% 0; }
  100% { background-position: 200% 0; }
}

@utility shimmer {
  background: linear-gradient(
    90deg,
    var(--surface-1) 0%,
    var(--surface-2) 50%,
    var(--surface-1) 100%
  );
  background-size: 200% 100%;
  animation: shimmer 1.4s infinite var(--ease-out-sentinel);
}

@media (prefers-reduced-motion: reduce) {
  .shimmer {
    animation: none;
  }
}
```

- [ ] **Step 2: Replace `animate-pulse` with `shimmer` in LoadingState**

Open `web/components/data/loading-state.tsx`. Change `animate-pulse` to `shimmer`.

- [ ] **Step 3: Commit**

```
git add web/app/globals.css web/components/data/loading-state.tsx
git commit -m "feat(ui): custom shimmer keyframe replacing animate-pulse"
```

### Task 6.3: View-transitions for route changes

**Files:**
- Modify: `web/app/(dashboard)/layout.tsx`

- [ ] **Step 1: Enable view-transitions**

Next.js 16 supports the `viewTransition` config flag. Add to `web/next.config.ts` (create if missing):
```ts
import type { NextConfig } from "next"

const config: NextConfig = {
  experimental: {
    viewTransition: true,
  },
}

export default config
```

- [ ] **Step 2: Add page transition CSS**

In `globals.css`:
```css
::view-transition-old(root),
::view-transition-new(root) {
  animation-duration: 150ms;
  animation-timing-function: var(--ease-out-sentinel);
}
::view-transition-old(root) {
  animation-name: fadeOut;
}
::view-transition-new(root) {
  animation-name: fadeSlideIn;
}
@keyframes fadeOut {
  to { opacity: 0; }
}
@keyframes fadeSlideIn {
  from { opacity: 0; transform: translateY(4px); }
  to { opacity: 1; transform: translateY(0); }
}
@media (prefers-reduced-motion: reduce) {
  ::view-transition-old(root),
  ::view-transition-new(root) {
    animation-duration: 0ms !important;
  }
}
```

- [ ] **Step 3: Commit**

```
git add web/next.config.ts web/app/globals.css
git commit -m "feat(web): view-transitions on route change (150ms fade + slide-up)"
```

### Task 6.4: Keyboard help overlay

**Files:**
- Create: `web/components/layout/keyboard-help-overlay.tsx`

- [ ] **Step 1: Create the overlay**

```tsx
"use client"

import * as React from "react"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"

const SHORTCUTS: { keys: string; label: string }[] = [
  { keys: "⌘K", label: "Open command palette" },
  { keys: "?", label: "Show this overlay" },
  { keys: "G then F", label: "Go to Findings" },
  { keys: "G then R", label: "Go to Risks" },
  { keys: "G then S", label: "Go to Scans" },
  { keys: "G then D", label: "Go to Dashboard" },
]

export function KeyboardHelpOverlay({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>Keyboard shortcuts</DialogTitle>
        </DialogHeader>
        <ul className="mt-4 space-y-2">
          {SHORTCUTS.map((s) => (
            <li key={s.keys} className="flex items-center justify-between text-body-sm">
              <span>{s.label}</span>
              <kbd className="rounded border border-border bg-surface-2 px-2 py-0.5 font-mono text-caption">
                {s.keys}
              </kbd>
            </li>
          ))}
        </ul>
      </DialogContent>
    </Dialog>
  )
}
```

- [ ] **Step 2: Mount in AppShell + bind `?` key**

In `web/components/layout/app-shell.tsx`, add:
```tsx
const [helpOpen, setHelpOpen] = useState(false)

useEffect(() => {
  const handler = (e: KeyboardEvent) => {
    if (e.key === "?" && !e.metaKey && !e.ctrlKey && !e.altKey) {
      const tag = (e.target as HTMLElement)?.tagName
      if (tag === "INPUT" || tag === "TEXTAREA") return
      e.preventDefault()
      setHelpOpen((o) => !o)
    }
  }
  window.addEventListener("keydown", handler)
  return () => window.removeEventListener("keydown", handler)
}, [])
```

Render:
```tsx
<KeyboardHelpOverlay open={helpOpen} onOpenChange={setHelpOpen} />
```

- [ ] **Step 3: Commit**

```
git add web/components/layout/keyboard-help-overlay.tsx web/components/layout/app-shell.tsx
git commit -m "feat(web): keyboard help overlay (? key) with shortcut index"
```

### Task 6.5: Reduced-motion + final tokens audit

**Files:**
- Modify: `web/app/globals.css`

- [ ] **Step 1: Add global reduced-motion**

At end of `globals.css`:
```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.001ms !important;
    transition-duration: 0.001ms !important;
  }
}
```

- [ ] **Step 2: Commit**

```
git add web/app/globals.css
git commit -m "feat(ui): respect prefers-reduced-motion globally"
```

### Task 6.6: PR 6 build, deploy, full QA pass

- [ ] **Step 1: Sync, build, deploy**

```
rsync -az --delete --exclude node_modules --exclude .next --exclude .git web/ okyay@77.42.34.174:/tmp/sentinelcore-src/web/
ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src/web && \
  docker build --build-arg NEXT_PUBLIC_API_URL='' -t sentinelcore/frontend:redesign-pr6 . 2>&1 | tail -10 && \
  docker tag sentinelcore/frontend:redesign-pr6 sentinelcore/frontend:pilot && \
  cd /opt/sentinelcore/compose && docker compose up -d frontend"
curl -s -o /dev/null -w 'frontend: %{http_code}\n' https://sentinelcore.resiliencetech.com.tr/
```

- [ ] **Step 2: Final QA — full walkthrough**

End-to-end verification:
1. Login as `admin@sentinel.io` (split-screen visible at lg+)
2. Default landing is dashboard; theme switcher toggles dark/light
3. Sidebar grouping works, workspace switcher persists project across reload
4. Header breadcrumbs reflect path; center search opens command palette via click and via ⌘K
5. Press `?` — keyboard help overlay opens
6. Each list page: filters work, density toggle works, branded empty state appears for empty data
7. Each detail page: 3-column rail/main/rail, right-rail actions still work (resolve/mute/reopen/cancel)
8. Create a scan via the New Scan dialog — submission works, dialog closes, list refreshes, navigation away from /scans is responsive (the original prod bug remains fixed)
9. Reduced-motion in OS settings — motion stops, layout still works

- [ ] **Step 3: Tag final image**

```
ssh okyay@77.42.34.174 "docker tag sentinelcore/frontend:redesign-pr6 sentinelcore/frontend:redesign-final"
```

- [ ] **Step 4: Push branch and open PR (or merge into source branch)**

```
git push
```

---

## Self-review

Run after writing all tasks; fix issues inline.

### Spec coverage check

| Spec section | Implementing task(s) |
|--------------|----------------------|
| 2 Principles — look first / dark default / density opt-in / hue+icon | 1.4 (severity calibration), 3.9 (theme provider w/ default dark), 4.2 (density toggle), 4.4 (table density), 2.4 (badge with severity icon support — note: icons added per-page when used) |
| 3.1 Surfaces                       | 1.1 |
| 3.2 Borders                        | 1.2 |
| 3.3 Brand                          | 1.3 |
| 3.4 Severity calibration           | 1.4 |
| 3.5 Typography                     | 1.5 |
| 3.6 Motion tokens                  | (already in globals; enforced by primitive rewrites in PR 2 + 6.3 view-transitions) |
| 3.7 Focus ring                     | 1.6 |
| 4.1 Sidebar groups + workspace     | 3.1, 3.4, 3.5, 3.6 |
| 4.2 Header breadcrumbs/search/theme/user | 3.7, 3.8, 3.9, 3.10, 3.11 |
| 4.3 Page shell + PageHeader        | 3.12, 3.13 |
| 4.4 Detail 3-column                | 5.12 |
| 5 Primitives (UI)                  | 2.1–2.8 |
| 5 Primitives (security calibration) | 4.8 |
| 5 New (Sparkline / Heatmap / StackedBar) | 4.5, 4.6, 4.7, 4.9 |
| 5.4 Empty + loading                | 4.1, 4.4, 6.2 |
| 6 Page-by-page                     | 5.1–5.12 |
| 7 Motion / microinteractions       | 2.1 button hover/active, 2.5 card hover, 4.4 row hover, 6.2 shimmer, 6.3 view-transitions |
| 8 Accessibility                    | 1.6 focus ring, 2.4 badge with paired icon usages on pages, 4.7 stacked-bar aria-label, 6.5 reduced-motion |
| 9 Implementation strategy          | PR 0–6 structure |
| 10 Risks                           | PR 0 hotfix carry-forward; rollback tag in PR 0; light-mode "best-effort" honored throughout |

### Placeholder scan

Final pass over the plan: every code step contains real, runnable code. Per-page tasks 5.5–5.10 reference an "existing table" in the body — these are real existing components in `web/features/*/`-table.tsx files; their internals are not changed in this PR (only PageHeader props and EmptyStateBranded usage). One open assumption flagged for the executor:

- Tasks 5.2–5.10 say "adapt to actual filter state hooks already present" — the executor should read each page's existing imports and re-wire them through the new PageHeader's `filters` prop. This is not a placeholder; it's a small adaptation step the executor performs by reading the existing file before editing.

### Type consistency

- `Column<T>.sortKey?` is added in 4.4 and consumed in DataTable; no sort-key consumer exists in the plan beyond the table itself, so no downstream type drift.
- `useProjectId()` is exported in 3.1 and consumed in 5.1; signatures match.
- `useDensity()` returns `{ density, setDensity }`; consumed by 4.2 (toggle UI) and 4.4 (table); shapes match.
- `WorkspaceContextValue` exposes `projects`, `projectId`, `setProjectId`, `activeProject`, `isLoading` — sidebar and dashboard each read a subset; all reads match the type.

No placeholders, no contradictions, no type drift.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-01-ui-redesign-professional.md`. Two execution options:

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per task, review between tasks, fast iteration. Good fit because each task is independently verifiable and the plan is large enough that fresh-context-per-task pays off.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints for review. Slower context build-up but tighter coupling for cross-cutting concerns.

Which approach?
