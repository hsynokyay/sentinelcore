# Phase 1 Execution Notes

## Task 9.1 — Frontend useAuth + Can: SKIPPED

**Reason:** The `web/` directory does not exist on the `main` branch. The SentinelCore Next.js frontend lives on branch `phase2/api-dast` where Phase 2 was built. To execute Task 9.1:

1. Either merge the frontend from `phase2/api-dast` into `main` first (out of Phase 1 scope), or
2. Execute Task 9.1 separately as a follow-up once the frontend is on `main`.

The backend changes in Phase 1 (RBAC cache, `/auth/me` endpoint, `RequirePermission` middleware) are fully deployable without the frontend gating. UI-level gating is cosmetic — the middleware enforces the actual authorization.

## Task 7.3 — Route wrapping: SCOPE REDUCED

The plan listed 80 routes across 19 groups; `main` has only 21 authenticated routes (7 groups: organizations, teams, users, projects, scan-targets, scans, findings). All 21 existing routes were wrapped. The remaining 59 routes (risks, webhooks, reports, surface, ops, audit, governance, auth-profiles, source-artifacts, api-keys, retention, notifications) don't exist on this branch — they live on `phase2/api-dast` and will need to be wrapped when that branch's handlers land on `main`.
