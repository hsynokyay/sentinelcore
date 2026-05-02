# Phase 4: Enterprise Governance, Reporting, and Operational Hardening

**Status:** Implemented
**Branch:** phase2/api-dast

## Overview

Phase 4 adds enterprise governance capabilities to SentinelCore, transforming it from a scanning engine into a full AppSec platform with workflow controls, notifications, retention management, and reporting.

## New Components

### Packages

| Package | Purpose |
|---------|---------|
| `internal/governance/` | Triage workflow, approval engine, assignment, SLA, emergency stop, retention lifecycle |
| `internal/notification/` | In-app notifications, webhook delivery with SSRF validation and HMAC signing |

### Binaries

| Binary | Purpose |
|--------|---------|
| `cmd/retention-worker/` | Hourly CronJob: approval expiry, retention transitions, SLA violation detection |
| `cmd/notification-worker/` | NATS consumer: notification fan-out, webhook delivery with retry |

## Database Schema

Migration: `migrations/014_governance.up.sql` / `migrations/014_governance.down.sql`

### New Tables (governance schema)

| Table | Purpose |
|-------|---------|
| `governance.org_settings` | Per-org governance configuration (approval requirements, SLA days, retention policies) |
| `governance.approval_requests` | Pending/decided approval records |
| `governance.finding_assignments` | Finding ownership tracking |
| `governance.sla_violations` | SLA breach records |
| `governance.notifications` | In-app notification store |
| `governance.webhook_configs` | Webhook endpoint configurations (secrets AES-256-GCM encrypted) |
| `governance.webhook_deliveries` | Delivery attempts with retry tracking |
| `governance.retention_records` | Resource lifecycle tracking (active → archived → purge_pending → purged) |
| `governance.emergency_stops` | Kill switch activations |

### Modified Tables

- `findings.findings`: added `org_id`, `assigned_to`, `sla_deadline`, `legal_hold`
- `scans.scan_jobs`: added `emergency_stopped`, `stopped_by`, `stopped_reason`

### RLS Policies

All governance tables have RLS enabled with appropriate policies:
- Team-scoped: approval_requests, finding_assignments (via team_memberships join)
- User-scoped: notifications (visible only to recipient)
- Org-scoped: webhook_configs, retention_records, emergency_stops, org_settings

## API Endpoints (33 new routes)

### Governance Settings
- `GET /api/v1/governance/settings` — Read org governance configuration
- `PUT /api/v1/governance/settings` — Update governance configuration

### Approvals
- `GET /api/v1/governance/approvals` — List approval requests
- `GET /api/v1/governance/approvals/:id` — Get approval details
- `POST /api/v1/governance/approvals/:id/decide` — Approve or reject

### Emergency Stop
- `POST /api/v1/governance/emergency-stop` — Activate kill switch
- `POST /api/v1/governance/emergency-stop/lift` — Lift (four-eyes enforced)
- `GET /api/v1/governance/emergency-stop/active` — List active stops

### Finding Extensions
- `POST /api/v1/findings/:id/assign` — Assign finding ownership
- `POST /api/v1/findings/:id/legal-hold` — Set/remove legal hold

### Notifications
- `GET /api/v1/notifications` — List user notifications
- `POST /api/v1/notifications/:id/read` — Mark read
- `POST /api/v1/notifications/read-all` — Mark all read
- `GET /api/v1/notifications/unread-count` — Get unread count

### Webhooks
- `GET /api/v1/webhooks` — List webhook configs
- `POST /api/v1/webhooks` — Create webhook (SSRF validated)
- `PUT /api/v1/webhooks/:id` — Update webhook
- `DELETE /api/v1/webhooks/:id` — Delete webhook
- `POST /api/v1/webhooks/:id/test` — Test delivery

### Retention
- `GET /api/v1/retention/policies` — Read retention policies
- `PUT /api/v1/retention/policies` — Update retention policies
- `GET /api/v1/retention/records` — List retention records
- `GET /api/v1/retention/stats` — Retention statistics

### Reports
- `GET /api/v1/reports/findings-summary` — Severity/status/type breakdown
- `GET /api/v1/reports/triage-metrics` — Open/closed/assigned/overdue counts
- `GET /api/v1/reports/compliance-status` — Audit/retention/SLA compliance
- `GET /api/v1/reports/scan-activity` — Scan counts and coverage

## RBAC Permissions (13 new)

| Permission | platform_admin | security_admin | appsec_analyst | auditor |
|-----------|:-:|:-:|:-:|:-:|
| governance.settings.read | Y | Y | - | Y |
| governance.settings.write | Y | Y | - | - |
| governance.approvals.read | Y | Y | Y | Y |
| governance.approvals.decide | Y | Y | - | - |
| governance.emergency_stop.activate | Y | Y | - | - |
| governance.emergency_stop.lift | Y | - | - | - |
| findings.legal_hold | Y | Y | - | - |
| webhooks.read | Y | Y | Y | Y |
| webhooks.manage | Y | Y | - | - |
| retention.read | Y | Y | - | Y |
| retention.manage | Y | - | - | - |
| reports.read | Y | Y | Y | Y |

## Security Controls

- **Four-eyes principle**: Emergency stop activator cannot lift their own stop
- **Self-approval forbidden**: Approval requester cannot decide their own request
- **Finding transition matrix**: Invalid status transitions return 422
- **Legal hold blocks purge**: Records with legal_hold=true are never purged
- **Webhook SSRF validation**: 16 blocked CIDR ranges, re-validated at delivery time
- **Webhook signatures**: HMAC-SHA256 with `X-Sentinel-Signature` header
- **RLS on all tables**: Team-membership-based isolation matching existing model
- **UpdateFindingStatus RLS fix**: Now uses db.WithRLS (was previously bypassing RLS)

## NATS Subjects

| Subject | Purpose |
|---------|---------|
| `governance.estop.activated` | Emergency stop activation broadcast |
| `governance.estop.lifted` | Emergency stop lift broadcast |
| `governance.notifications` | Notification event fan-out |

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| RETENTION_INTERVAL | 3600 | Retention worker cycle interval (seconds) |
| WEBHOOK_DELIVERY_INTERVAL | 30 | Webhook delivery poll interval (seconds) |
