# SentinelCore Audit Action Taxonomy

Every action code emitted into `audit.audit_log` must appear here AND as a
typed constant in `pkg/audit/actions.go`. The CI test
`TestActionTaxonomyDriftCheck` in that package fails if the two sources
drift.

**Naming rules:**

- Lowercase, dot-separated, 2-4 segments: `<domain>.<resource>.<verb>`
- Past tense for completed actions (`created`, `resolved`, `failed`)
- Actions are append-only: never rename an existing code; deprecate with
  a new code and leave the old one defined for historical data.

**Shape:** the RE2 regex
`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,3}$` is enforced by a test.

---

## Authentication & identity

| Code | Emitted by | Notes |
|---|---|---|
| `auth.login.succeeded` | `internal/controlplane/api/auth.go` Login | email in details, never the password |
| `auth.login.failed` | same | includes `reason: bad_password | disabled | rate_limited` |
| `auth.logout` | same Logout | |
| `auth.refresh.succeeded` | Refresh | |
| `auth.refresh.failed` | Refresh | invalid refresh token |
| `auth.sso.login.succeeded` | `internal/controlplane/api/sso.go` SSOCallback | includes `provider_slug`, `jit_created` |
| `auth.sso.login.failed` | same | mirrors `auth.sso_login_events.error_code` |
| `auth.sso.logout` | SSOLogout | |
| `auth.password.changed` | user settings handler | |
| `auth.password.reset_requested` | password-reset flow | |
| `auth.break_glass.activated` | CLI break-glass | physical-access fallback |

## RBAC & membership

| Code | Emitted by | Notes |
|---|---|---|
| `rbac.role.created` | admin RBAC handler | |
| `rbac.role.updated` | same | |
| `rbac.role.deleted` | same | |
| `rbac.permission.granted` | role-permission mutation | |
| `rbac.permission.revoked` | same | |
| `user.created` | user admin handler | |
| `user.updated` | same | |
| `user.disabled` | same | |
| `user.enabled` | same | |
| `user.team_membership.added` | team admin handler | |
| `user.team_membership.removed` | same | |

## API keys

| Code | Emitted by | Notes |
|---|---|---|
| `apikey.created` | `apikeys.go` CreateAPIKey | scopes recorded; plaintext never |
| `apikey.rotated` | RotateAPIKey | |
| `apikey.revoked` | RevokeAPIKey | |
| `apikey.used` | `pkg/auth/middleware.go` | sampled at 1/N (env `AUDIT_APIKEY_SAMPLE_RATE`); denied always logged |
| `apikey.scope.changed` | when user's role change triggers scope trim | |

## Scans & findings

| Code | Emitted by | Notes |
|---|---|---|
| `scan.triggered` | scans.go CreateScan | |
| `scan.cancelled` | scans.go CancelScan | |
| `scan.completed` | sast/dast worker completion | |
| `scan.failed` | same | includes terminal error class |
| `finding.created` | correlation engine | bulk events — see cardinality budget |
| `finding.status.changed` | findings.go UpdateFindingStatus | |
| `finding.assigned` | AssignFinding | |
| `finding.annotation.added` | annotation handler | |
| `finding.legal_hold.set` | SetLegalHold | |
| `finding.legal_hold.cleared` | ClearLegalHold | |

## Risks (projected into `audit.risk_events`)

| Code | Emitted by | Notes |
|---|---|---|
| `risk.created` | `internal/risk/worker.go` | first detection |
| `risk.seen_again` | same | re-detection; material only if last seen ≥ 7d ago |
| `risk.score.changed` | same | material only if |Δ| ≥ 0.5 |
| `risk.status.changed` | risks handler + worker | always material |
| `risk.relation.added` | correlator | finding linked |
| `risk.relation.removed` | correlator | finding unlinked |
| `risk.evidence.changed` | correlator | evidence fingerprint differs |
| `risk.resolved` | risks handler | user action |
| `risk.reopened` | same | |
| `risk.muted` | same | |
| `risk.unmuted` | same | |
| `risk.assigned` | assignment handler | |
| `risk.note.added` | note handler | |
| `correlation.rebuild.triggered` | RebuildRisks | project-level |

## Governance (Phase 4)

| Code | Emitted by |
|---|---|
| `governance.approval.requested` | workflow.go Create |
| `governance.approval.approved` | workflow.go Decide |
| `governance.approval.rejected` | same |
| `governance.approval.expired` | retention-worker sweep |
| `governance.emergency_stop.activated` | estop.go Activate |
| `governance.emergency_stop.lifted` | estop.go Lift |
| `governance.sla.violated` | sla.go detector |
| `governance.sla.resolved` | same |

## SSO provider config (Phase 3)

| Code | Emitted by |
|---|---|
| `sso.provider.created` | sso_providers.go CreateSSOProvider |
| `sso.provider.updated` | UpdateSSOProvider |
| `sso.provider.deleted` | DeleteSSOProvider |
| `sso.mapping.upserted` | sso_group_mappings.go Create |
| `sso.mapping.deleted` | Delete |

## Webhooks & notifications

| Code | Emitted by |
|---|---|
| `webhook.config.created` | webhooks handler |
| `webhook.config.updated` | same |
| `webhook.config.deleted` | same |
| `webhook.delivery.attempted` | notification-worker |
| `webhook.delivery.succeeded` | same |
| `webhook.delivery.failed` | same |
| `notification.dispatched` | notification-worker |

## Configuration & system

| Code | Emitted by |
|---|---|
| `config.setting.changed` | settings handlers |
| `config.retention_policy.updated` | retention policy handler |
| `config.scan_quota.changed` | quota handler |
| `system.worker.started` | every worker at boot |
| `system.worker.stopped` | SIGTERM handler |
| `system.migration.applied` | startup migration runner |
| `system.backup.succeeded` | backup job |
| `system.backup.failed` | same |

## Meta — audit about audit

| Code | Emitted by |
|---|---|
| `audit.export.requested` | audit_export.go POST |
| `audit.export.downloaded` | download endpoint |
| `audit.integrity.check.passed` | hourly verifier |
| `audit.integrity.check.failed` | same |
| `audit.hmac_key.rotated` | key rotation CLI |
| `audit.hmac_key.missing` | verifier couldn't find a key version |
| `audit.global_access.granted` | platform_admin cross-tenant read |
| `audit.partition.purged` | manual purge after legal-hold clearance |
