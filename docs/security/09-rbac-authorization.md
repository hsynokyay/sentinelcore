# 9. RBAC and Authorization Model

## 9.1 Authorization Architecture

SentinelCore uses a three-layer authorization model:

```
┌───────────────────────────────────────────────────────────┐
│ Layer 1: API Gateway                                      │
│  • Authentication verification (JWT / session)            │
│  • Rate limiting                                          │
│  • Basic role presence check                              │
├───────────────────────────────────────────────────────────┤
│ Layer 2: Policy Engine (OPA)                              │
│  • Fine-grained RBAC evaluation                           │
│  • Resource-level access control                          │
│  • Policy-based decisions (scan scope, gate criteria)     │
├───────────────────────────────────────────────────────────┤
│ Layer 3: Database (Row-Level Security)                    │
│  • Team-scoped data isolation                             │
│  • Defense-in-depth enforcement                           │
│  • Cannot be bypassed by application bugs                 │
└───────────────────────────────────────────────────────────┘
```

## 9.2 Role Hierarchy

### 9.2.1 Global Roles (Organization-Wide)

| Role | Description | Scope |
|---|---|---|
| `platform_admin` | Full platform control. User management, global policies, system configuration. | Organization-wide |
| `security_director` | Read-all findings, manage global policies, generate org-wide reports. Cannot manage users or system config. | Organization-wide |
| `auditor` | Read-only access to all audit logs, findings, reports, and policies. Cannot modify anything. | Organization-wide |

### 9.2.2 Team Roles (Team-Scoped)

| Role | Description | Scope |
|---|---|---|
| `team_admin` | Manage team membership, team projects, team policies. Full access within team. | Team |
| `security_lead` | Create/manage scans, triage findings, manage scan targets and credentials within team projects. | Team |
| `analyst` | Run scans, view findings, add annotations, generate reports. Cannot modify configuration. | Team |
| `developer` | View findings for their projects, add comments, mark findings as resolved. Limited scan trigger. | Team |
| `viewer` | Read-only access to team findings and reports. | Team |

### 9.2.3 Service Roles (System-Internal)

| Role | Description |
|---|---|
| `svc_orchestrator` | Dispatch scans, manage worker state, create NetworkPolicies |
| `svc_sast_worker` | Read rules, publish SAST results, upload evidence |
| `svc_dast_worker` | Read rules, request auth sessions, publish DAST results, upload evidence |
| `svc_correlator` | Read/write findings, read vuln intelligence |
| `svc_audit` | Append-only write to audit log tables |
| `svc_vuln_intel` | Read/write vulnerability intelligence data |
| `svc_reporter` | Read findings, scans, projects; write reports |

## 9.3 Permission Matrix

### 9.3.1 Project Permissions

| Permission | platform_admin | security_director | team_admin | security_lead | analyst | developer | viewer |
|---|---|---|---|---|---|---|---|
| Create project | Y | N | Y | N | N | N | N |
| Update project | Y | N | Y | Y | N | N | N |
| Delete project | Y | N | Y | N | N | N | N |
| View project | Y | Y | Y | Y | Y | Y | Y |

### 9.3.2 Scan Permissions

| Permission | platform_admin | security_director | team_admin | security_lead | analyst | developer | viewer |
|---|---|---|---|---|---|---|---|
| Create scan | Y | N | Y | Y | Y | Y* | N |
| Cancel scan | Y | N | Y | Y | Y | N | N |
| View scan results | Y | Y | Y | Y | Y | Y | Y |
| Modify scan config | Y | N | Y | Y | N | N | N |
| Manage scan targets | Y | N | Y | Y | N | N | N |
| Manage scan schedules | Y | N | Y | Y | N | N | N |

*Developer can trigger scans only for projects they are assigned to, and only for SAST (not DAST).

### 9.3.3 Finding Permissions

| Permission | platform_admin | security_director | team_admin | security_lead | analyst | developer | viewer |
|---|---|---|---|---|---|---|---|
| View findings | Y | Y | Y | Y | Y | Y | Y |
| Triage findings | Y | Y | Y | Y | Y | N | N |
| Accept risk | Y | Y | Y | Y | N | N | N |
| Mark false positive | Y | Y | Y | Y | Y | N | N |
| Mark resolved | Y | Y | Y | Y | Y | Y | N |
| Add annotations | Y | Y | Y | Y | Y | Y | N |
| Export findings | Y | Y | Y | Y | Y | N | N |

### 9.3.4 Policy Permissions

| Permission | platform_admin | security_director | team_admin | security_lead | analyst | developer | viewer |
|---|---|---|---|---|---|---|---|
| Create global policy | Y | Y | N | N | N | N | N |
| Create team policy | Y | Y | Y | N | N | N | N |
| Assign policy | Y | Y | Y | N | N | N | N |
| View policy | Y | Y | Y | Y | Y | Y | Y |

### 9.3.5 Credential Permissions

| Permission | platform_admin | security_director | team_admin | security_lead | analyst | developer | viewer |
|---|---|---|---|---|---|---|---|
| Create auth config | Y | N | Y | Y | N | N | N |
| Update auth config | Y | N | Y | Y | N | N | N |
| Delete auth config | Y | N | Y | Y | N | N | N |
| View auth config (redacted) | Y | N | Y | Y | Y | N | N |

### 9.3.6 Administration Permissions

| Permission | platform_admin | security_director | auditor | team_admin | Other |
|---|---|---|---|---|---|
| Manage users | Y | N | N | N | N |
| Manage teams | Y | N | N | Y (own team) | N |
| System configuration | Y | N | N | N | N |
| View audit logs | Y | Y | Y | Y (own team) | N |
| Apply updates | Y | N | N | N | N |
| Manage Vault | Y | N | N | N | N |
| View platform metrics | Y | Y | Y | Y | N |

## 9.4 OPA Policy Implementation

### 9.4.1 Policy Structure

```
policies/
├── rbac/
│   ├── roles.rego          # Role definitions
│   ├── permissions.rego    # Permission assignments
│   └── inheritance.rego    # Role hierarchy rules
├── scan/
│   ├── scope.rego          # Scan scope enforcement
│   ├── targets.rego        # Target validation
│   └── schedules.rego      # Schedule limits
├── gate/
│   ├── cicd.rego           # CI/CD gate criteria
│   └── severity.rego       # Severity thresholds
├── data/
│   ├── retention.rego      # Retention enforcement
│   └── export.rego         # Export controls
└── system/
    ├── immutable.rego      # System policy protections
    └── admin.rego          # Admin action controls
```

### 9.4.2 Example RBAC Policy (Rego)

```rego
package sentinelcore.rbac

import future.keywords.if
import future.keywords.in

# Determine effective permissions for the current request
default allow := false

allow if {
    some permission in effective_permissions
    permission == required_permission
}

# Resolve effective permissions from role
effective_permissions[perm] if {
    some role in input.actor.roles
    some perm in role_permissions[role]
}

# Team-scoped access check
team_access if {
    input.resource.team_id in input.actor.team_ids
}

# Global role bypasses team check
team_access if {
    input.actor.global_role in {"platform_admin", "security_director", "auditor"}
}

# Final authorization decision
allow if {
    team_access
    some perm in effective_permissions
    perm == input.required_permission
}
```

### 9.4.3 Scan Scope Policy (Rego)

```rego
package sentinelcore.scan.scope

import future.keywords.if
import future.keywords.in

default allow_target := false

# Verify DAST scan target is within approved scope
allow_target if {
    target := input.scan_target
    approved := input.approved_targets[_]

    # Domain must be in allowlist
    target.domain in approved.allowed_domains

    # Port must be in allowlist
    target.port in approved.allowed_ports

    # Must not be a private IP (anti-SSRF)
    not is_private_ip(target.resolved_ip)

    # Path must match allowed prefixes (if configured)
    path_allowed(target.path, approved.allowed_paths)
}

is_private_ip(ip) if {
    net.cidr_contains("10.0.0.0/8", ip)
}
is_private_ip(ip) if {
    net.cidr_contains("172.16.0.0/12", ip)
}
is_private_ip(ip) if {
    net.cidr_contains("192.168.0.0/16", ip)
}
is_private_ip(ip) if {
    net.cidr_contains("127.0.0.0/8", ip)
}
```

## 9.5 Multi-Team Isolation

### 9.5.1 Data Isolation Guarantees

- Teams can only see projects assigned to their team
- Findings are visible only to the owning team's members
- Cross-team data access requires `security_director` or `platform_admin` role
- Database RLS enforces isolation independently of application logic
- Audit logs show cross-team access by elevated roles

### 9.5.2 Resource Quotas

Team-level resource quotas prevent noisy-neighbor effects:

| Resource | Default Quota | Configurable |
|---|---|---|
| Concurrent scans | 5 per team | Yes |
| Projects | 100 per team | Yes |
| Scan targets | 50 per project | Yes |
| Findings storage | 1 million per team | Yes |
| Report generation | 10 per hour | Yes |

## 9.6 API Key Scoping

CI/CD API keys are scoped with minimum required permissions:

```json
{
  "key_id": "sk_live_abc123",
  "scopes": [
    "scan:create",
    "scan:status",
    "findings:read"
  ],
  "constraints": {
    "project_ids": ["uuid-1", "uuid-2"],
    "scan_types": ["sast"],
    "ip_allowlist": ["10.0.0.0/8"]
  },
  "expires_at": "2027-03-14T00:00:00Z",
  "created_by": "uuid-admin",
  "created_at": "2026-03-14T00:00:00Z"
}
```

## 9.7 Approval Workflows

Critical actions require multi-party approval:

| Action | Approval Requirement |
|---|---|
| Add new DAST scan target | security_lead or higher |
| Modify scan scope (expand domains) | team_admin + security_lead |
| Accept risk on critical finding | security_lead + security_director |
| Modify global policy | platform_admin (logged and audited) |
| Create platform_admin user | Existing platform_admin (dual approval) |
| Apply platform update | platform_admin (logged and audited) |
| Delete project | team_admin (soft delete; hard delete requires platform_admin) |
