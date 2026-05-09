# Phase 2 → Main Integration — Design

**Status:** Draft, awaiting product decisions.
**Open PRs blocked on this:** #1 (`phase2/api-dast → main`, 78 conflicts) and #2 (`feature/iac-phase1-rbac → main`, 16 conflicts).
**Origin:** Discovered during the 2026-05-09 PR-cleanup session — every other open PR was merged successfully (#3, #8, #14–#17). #1 and #2 hit the same architectural wall.

---

## 1. The problem

`main` and `phase2/api-dast` have evolved in parallel for ~3 months and now contain three independent designs of the same subsystem:

| Subsystem | `main` design | `phase2/api-dast` design |
|---|---|---|
| **Data access** | `pkg/tenant.TxUser(ctx, pool, orgID, userID, fn)` wraps every query in a tenant-scoped tx with RLS active | Raw `h.pool.Query(ctx, ...)` with WHERE filters; no RLS enforcement |
| **Approval workflow** | Phase 9 Wave 1 — finite-state-machine + SLA deadlines + reviewer assignment | A1–A6 — two-person closure approvals + triage execution + audit trail (just merged via PR #17) |
| **Auth** | OIDC SSO via `coreos/go-oidc` + `golang.org/x/oauth2` | Cookie-session + JWT (existing `pkg/auth`) |
| **Build hardening** | Pinned base-image digests, `-trimpath`, `-ldflags="-s -w"`, seccomp profiles, read-only containers, tmpfs scratch | VPS-deployed compose with seccomp relaxed, joined to external `securecontext-nginx` |

Both `main` and `phase2/api-dast` independently added handlers, web pages, RBAC permissions, and DB schema for *the same product features*. A naive merge — even with careful per-hunk resolution — will either silently delete one of these implementations or produce code that compiles but doesn't function.

PR #2 (IAC Phase 1 RBAC → main) hits the same `tenant.TxUser` boundary because RBAC sits exactly where main adopted RLS.

---

## 2. Decisions required (product / architecture)

The merge cannot proceed without four decisions. These are not code questions — they are product/architecture questions that engineering should not answer unilaterally.

### 2.1 Approval workflow: Phase 9 FSM or A1–A6?

- **Phase 9 FSM** (main) models approvals as a state machine with SLA deadlines. Generic — can express any approval shape.
- **A1–A6** (phase2) hard-codes "two-person closure approval" — the specific governance flow the Phase 4 spec called out as required for SOC 2 / ISO 27001 alignment.

**Possible answers:**
- (a) FSM is the future, retire A1–A6. Cost: lose explicit two-person closure UI; rebuild that workflow on top of FSM.
- (b) A1–A6 is the deployed reality, FSM was a prototype. Cost: lose generic FSM machinery; future approval shapes need bespoke code.
- (c) Compose: FSM is the engine, A1–A6 is one workflow definition that runs on it. Cost: integration work (~1 sprint).

### 2.2 Data-access pattern: adopt `tenant.TxUser` everywhere?

If we keep `tenant.TxUser` from main (recommended for security — RLS is a meaningful defense-in-depth layer), every phase2 handler that uses raw `h.pool.Query` must be ported. Approximate scope:

| Package | Files needing port |
|---|---|
| `internal/controlplane/api` | All ~25 handlers added/modified on phase2 (governance_exports, source_artifacts, scan_targets, exports, reports, risks, ...) |
| `internal/governance/exportworker` | New worker added in PR #17 — reads + writes export jobs |
| `internal/governance` (workflow, transitions, triage, etc.) | Moderate touchups; most reads are within service boundaries already |

Port pattern is mechanical (wrap each query in `tenant.TxUser`), but the test surface is large. Estimated effort: **2–3 days** for the full govops surface.

### 2.3 Auth: OIDC SSO or cookie-session?

- **OIDC SSO** (main) — federated identity via Keycloak / Okta / Auth0. Required for any enterprise sale.
- **Cookie-session** (phase2) — local accounts, simpler operator setup, no IdP dependency.

**Possible answers:**
- (a) OIDC is the production direction; phase2 cookie sessions stay only as a dev/CI fallback.
- (b) Both, configurable per deployment. Cost: keep two code paths in `pkg/auth` middleware.

### 2.4 Build hardening: re-enable on phase2's deployed compose?

Phase 8 main pinned digests, dropped capabilities, enabled seccomp. Recent phase2 commit `f7348c63` *explicitly relaxed* these "for VPS compatibility". Either:

- (a) Diagnose and fix the VPS-compat issue, re-enable hardening on the merged compose.
- (b) Accept the relaxation as the production reality; document the risk.

---

## 3. Recommended sequencing

1. **Decide §2.1–§2.4** in a 30-min sync. Capture in this doc as an ADR appendix.
2. **Write a focused implementation plan** (separate `docs/superpowers/plans/...` doc) that, given those decisions, is mechanical.
3. **Execute the merge** in a single dedicated session (estimated 1–3 days depending on §2.2 scope), in an isolated branch, with full build + test verification before pushing.
4. **Open #1 and #2 as fresh PRs** against the merged branch (the existing PRs can be closed — the resolved branch is the new artifact).

The current open PRs (#1, #2) should *not* be merged via "Resolve conflicts" in the GitHub UI — that path silently picks one side per conflict region, which is exactly the failure mode this doc warns against.

---

## 4. What's safe to do *without* the decisions

- Land any non-conflicting feature work on `phase2/api-dast` (current development home).
- Land bug fixes that touch files outside the conflict surface (auth, governance, the API handlers listed in §2.2).
- Continue to merge stacked DAST/govops branches into `phase2/api-dast`.

What is *not* safe: cherry-picking individual phase2 commits to main, or vice versa, on the assumption that "this one file isn't conflicting." The conflict surface is wide and shifts as branches evolve.

---

## 5. ADR appendix (to be filled in)

| Decision | Resolved? | Rationale | Decided by | Date |
|---|---|---|---|---|
| §2.1 Approval workflow | ☐ |  |  |  |
| §2.2 `tenant.TxUser` adoption | ☐ |  |  |  |
| §2.3 Auth strategy | ☐ |  |  |  |
| §2.4 Build hardening on prod compose | ☐ |  |  |  |
