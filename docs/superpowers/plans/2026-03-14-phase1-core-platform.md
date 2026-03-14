# SentinelCore Phase 1: Core Platform Foundation

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the foundational backend platform — database, RBAC, audit logging, Control Plane API, minimal SAST worker, vulnerability intelligence ingestion, and secure update verification — that all subsequent phases build upon.

**Architecture:** Go monorepo with 6 deployable services (Control Plane, Policy Engine, Audit Service, SAST Worker, Vuln Intel Service, Update Manager) sharing common libraries (`pkg/*`). PostgreSQL with schema-level isolation and RLS. NATS JetStream for async messaging. Redis for sessions and rate limiting. MinIO for evidence. All services communicate via gRPC internally and emit audit events to NATS.

**Tech Stack:** Go 1.22+, PostgreSQL 16, NATS 2.10+ (JetStream), Redis 7, MinIO, golang-migrate, zerolog, prometheus/client_golang, google.golang.org/grpc, github.com/golang-jwt/jwt/v5, github.com/redis/go-redis/v9

---

## Phase 1 Goals

At the end of Phase 1, an engineer can:

1. `docker-compose up -d` to start the entire platform locally
2. `sentinelcore-cli bootstrap --admin-email admin@local` to create the first admin
3. Authenticate via `POST /api/v1/auth/login` and receive a JWT
4. Create organizations, teams, projects, and scan targets via REST API
5. Trigger a SAST scan via API; a minimal worker picks it up, runs pattern matching, and produces findings
6. Query findings with team-scoped RLS isolation
7. Import a signed vulnerability intelligence bundle (NVD/OSV/GitHub Advisory format)
8. Import a signed update bundle and verify its Ed25519 trust chain
9. See every operation in the audit log
10. Observe that a non-admin user is blocked from admin endpoints (RBAC)
11. Observe that rate limiting rejects excessive API requests

---

## Phase 1 File Structure

```
sentinelcore/
├── cmd/
│   ├── controlplane/main.go          # Control Plane entry point
│   ├── policy-engine/main.go         # Policy Engine entry point
│   ├── audit-service/main.go         # Audit Log Service entry point
│   ├── sast-worker/main.go           # Minimal SAST worker entry point
│   ├── vuln-intel/main.go            # Vuln Intel Service entry point
│   ├── updater/main.go               # Update Manager entry point
│   └── cli/main.go                   # sentinelcore-cli entry point
├── pkg/
│   ├── db/
│   │   ├── pool.go                   # PostgreSQL connection pool
│   │   ├── migrate.go                # Migration runner (golang-migrate)
│   │   ├── rls.go                    # RLS session variable setup
│   │   └── pool_test.go
│   ├── nats/
│   │   ├── client.go                 # JetStream connection + stream setup
│   │   ├── consumer.go               # Durable consumer helper
│   │   ├── producer.go               # Publisher with retry
│   │   ├── signing.go                # Message HMAC signing/verification
│   │   └── client_test.go
│   ├── auth/
│   │   ├── jwt.go                    # JWT issue / validate
│   │   ├── session.go                # Redis session manager
│   │   ├── middleware.go             # HTTP/gRPC auth middleware
│   │   ├── password.go               # bcrypt hash/verify
│   │   └── jwt_test.go
│   ├── audit/
│   │   ├── emitter.go                # Audit event builder + NATS publish
│   │   ├── types.go                  # AuditEvent struct
│   │   └── emitter_test.go
│   ├── crypto/
│   │   ├── canonical.go              # Canonical JSON serialization
│   │   ├── ed25519.go                # Ed25519 sign/verify wrappers
│   │   ├── sha256.go                 # SHA-256 file hashing
│   │   ├── canonical_test.go         # Golden test vectors
│   │   └── ed25519_test.go
│   ├── config/
│   │   ├── loader.go                 # Layered config: defaults → env → file
│   │   └── loader_test.go
│   ├── observability/
│   │   ├── logger.go                 # zerolog structured logger
│   │   ├── metrics.go                # Prometheus metrics endpoint
│   │   └── health.go                 # Health check handler
│   ├── ratelimit/
│   │   ├── limiter.go                # Token bucket, Redis-backed
│   │   ├── middleware.go             # HTTP middleware
│   │   └── limiter_test.go
│   ├── grpc/
│   │   ├── server.go                 # gRPC server with interceptors
│   │   ├── interceptors.go           # Logging, auth, audit interceptors
│   │   └── health.go                 # gRPC health service
│   └── testutil/
│       ├── db.go                     # Test DB setup (Docker PostgreSQL)
│       ├── nats.go                   # In-process NATS test server
│       └── fixtures.go              # Test data factories
├── internal/
│   ├── controlplane/
│   │   ├── server.go                 # HTTP server setup, router, middleware chain
│   │   ├── api/
│   │   │   ├── auth.go               # POST /auth/login, /auth/refresh, /auth/logout
│   │   │   ├── organizations.go      # Org CRUD
│   │   │   ├── teams.go              # Team CRUD + membership
│   │   │   ├── projects.go           # Project CRUD
│   │   │   ├── scan_targets.go       # Scan target CRUD
│   │   │   ├── scans.go              # Scan lifecycle (create, get, cancel)
│   │   │   ├── findings.go           # Finding query, status update
│   │   │   ├── users.go              # User management
│   │   │   └── system.go             # Health, version, config
│   │   └── service/
│   │       ├── project_service.go    # Project business logic
│   │       ├── scan_service.go       # Scan creation, dispatch to NATS
│   │       ├── finding_service.go    # Finding queries with RLS
│   │       └── user_service.go       # User CRUD, password management
│   ├── policy/
│   │   ├── service.go                # gRPC server for policy evaluation
│   │   ├── rbac.go                   # Role-permission matrix
│   │   ├── scope.go                  # Scan scope validation
│   │   └── rbac_test.go
│   ├── audit/
│   │   ├── consumer.go               # NATS consumer → PostgreSQL writer
│   │   ├── writer.go                 # Batch INSERT into audit.audit_log
│   │   └── consumer_test.go
│   ├── sast/
│   │   ├── worker.go                 # NATS consumer, scan lifecycle
│   │   ├── analyzer.go               # Pattern matching engine
│   │   ├── rules.go                  # Rule loading from DB/file
│   │   ├── evidence.go               # Evidence packaging + MinIO upload
│   │   └── worker_test.go
│   ├── vuln/
│   │   ├── service.go                # gRPC server, lookup API
│   │   ├── ingest/
│   │   │   ├── nvd.go                # NVD JSON 2.0 parser
│   │   │   ├── osv.go                # OSV parser
│   │   │   ├── github.go             # GitHub Advisory parser
│   │   │   └── nvd_test.go
│   │   ├── normalizer.go             # Normalize to internal schema
│   │   ├── matcher.go                # Package version range matching
│   │   └── offline.go                # Signed bundle import
│   ├── updater/
│   │   ├── service.go                # gRPC server, import workflow
│   │   ├── verify.go                 # 25-step bundle verification
│   │   ├── trust.go                  # Trust store management
│   │   ├── lockdown.go               # DB-backed lockdown flag
│   │   └── verify_test.go
│   └── cli/
│       ├── bootstrap.go              # Bootstrap command
│       ├── update.go                 # Update trust commands
│       └── scan.go                   # Scan trigger command
├── api/
│   └── proto/
│       ├── policy/v1/policy.proto    # Policy evaluation service
│       ├── audit/v1/audit.proto      # Audit log service
│       ├── vuln/v1/vuln.proto        # Vuln intel service
│       └── updater/v1/updater.proto  # Update manager service
├── migrations/
│   ├── 001_create_schemas.up.sql
│   ├── 001_create_schemas.down.sql
│   ├── 002_core_tables.up.sql
│   ├── 002_core_tables.down.sql
│   ├── 003_scans_tables.up.sql
│   ├── 004_findings_tables.up.sql
│   ├── 005_vuln_intel_tables.up.sql
│   ├── 006_audit_tables.up.sql
│   ├── 007_rules_tables.up.sql
│   ├── 008_policies_tables.up.sql
│   ├── 009_updates_tables.up.sql
│   ├── 010_auth_tables.up.sql
│   ├── 011_rls_policies.up.sql
│   ├── 012_finding_immutability_trigger.up.sql
│   └── ... (corresponding .down.sql files)
├── deploy/
│   └── docker-compose/
│       ├── docker-compose.yml
│       ├── postgres-init.sql         # Create database + schemas
│       └── nats.conf                 # JetStream config
├── rules/
│   └── builtin/
│       └── sast-patterns.json        # Minimal built-in SAST rules
├── test/
│   └── integration/
│       ├── auth_rbac_test.go
│       ├── scan_pipeline_test.go
│       ├── audit_test.go
│       ├── vuln_intel_test.go
│       ├── update_trust_test.go
│       └── ratelimit_test.go
├── go.mod
├── go.sum
├── Makefile
└── Dockerfile
```

---

## Milestone 1: Repository Scaffold & Infrastructure

**Goal:** Go module initialized, Docker Compose runs PostgreSQL + NATS + Redis + MinIO, Makefile builds all binaries.

### Task 1.1: Initialize Go module and Makefile

**Files:**
- Create: `go.mod`, `Makefile`, `.gitignore`, `Dockerfile`

- [ ] Initialize Go module: `go mod init github.com/sentinelcore/sentinelcore`
- [ ] Create `Makefile` with targets:
  ```makefile
  SERVICES := controlplane policy-engine audit-service sast-worker vuln-intel updater cli

  .PHONY: build test lint migrate

  build:
  	@for svc in $(SERVICES); do \
  		echo "Building $$svc..."; \
  		go build -o bin/$$svc ./cmd/$$svc; \
  	done

  test:
  	go test ./... -race -count=1

  test-integration:
  	go test ./test/integration/... -race -count=1 -tags=integration

  lint:
  	golangci-lint run ./...

  proto:
  	buf generate

  migrate-up:
  	migrate -path migrations -database "$(DATABASE_URL)" up

  migrate-down:
  	migrate -path migrations -database "$(DATABASE_URL)" down 1

  docker-up:
  	docker-compose -f deploy/docker-compose/docker-compose.yml up -d

  docker-down:
  	docker-compose -f deploy/docker-compose/docker-compose.yml down
  ```
- [ ] Create multi-stage `Dockerfile` for all services (build arg selects which)
- [ ] `make build` compiles all binaries
- [ ] Commit: `chore: initialize repository scaffold`

### Task 1.2: Docker Compose environment

**Files:**
- Create: `deploy/docker-compose/docker-compose.yml`
- Create: `deploy/docker-compose/postgres-init.sql`
- Create: `deploy/docker-compose/nats.conf`

- [ ] Write `docker-compose.yml`:
  ```yaml
  services:
    postgres:
      image: postgres:16-alpine
      environment:
        POSTGRES_DB: sentinelcore
        POSTGRES_USER: sentinelcore
        POSTGRES_PASSWORD: dev-password
      ports: ["5432:5432"]
      volumes:
        - ./postgres-init.sql:/docker-entrypoint-initdb.d/01-init.sql
        - pgdata:/var/lib/postgresql/data
      healthcheck:
        test: ["CMD", "pg_isready", "-U", "sentinelcore"]
        interval: 5s
        retries: 5

    nats:
      image: nats:2.10-alpine
      command: ["-js", "-c", "/etc/nats/nats.conf"]
      ports: ["4222:4222", "8222:8222"]
      volumes:
        - ./nats.conf:/etc/nats/nats.conf

    redis:
      image: redis:7-alpine
      ports: ["6379:6379"]

    minio:
      image: minio/minio:latest
      command: ["server", "/data", "--console-address", ":9001"]
      environment:
        MINIO_ROOT_USER: minioadmin
        MINIO_ROOT_PASSWORD: minioadmin
      ports: ["9000:9000", "9001:9001"]
      volumes:
        - miniodata:/data

  volumes:
    pgdata:
    miniodata:
  ```
- [ ] Write `postgres-init.sql` to create 12 schemas:
  ```sql
  CREATE SCHEMA IF NOT EXISTS core;
  CREATE SCHEMA IF NOT EXISTS scans;
  CREATE SCHEMA IF NOT EXISTS findings;
  CREATE SCHEMA IF NOT EXISTS evidence;
  CREATE SCHEMA IF NOT EXISTS rules;
  CREATE SCHEMA IF NOT EXISTS vuln_intel;
  CREATE SCHEMA IF NOT EXISTS policies;
  CREATE SCHEMA IF NOT EXISTS audit;
  CREATE SCHEMA IF NOT EXISTS reports;
  CREATE SCHEMA IF NOT EXISTS updates;
  CREATE SCHEMA IF NOT EXISTS auth;
  CREATE SCHEMA IF NOT EXISTS cicd;
  ```
- [ ] Write `nats.conf` enabling JetStream with 2GB file storage
- [ ] `make docker-up` starts all services, `docker-compose ps` shows all healthy
- [ ] Commit: `chore: add Docker Compose dev environment`

**Tests:** `docker-compose ps` shows 4 healthy containers. `psql` connects. `nats-cli` publishes/receives.

---

## Milestone 2: Database Schema

**Goal:** All Phase 1 tables created via golang-migrate migrations. Includes RLS policies and the finding immutability trigger.

### Task 2.1: Core schema migrations

**Files:**
- Create: `migrations/001_create_schemas.up.sql` through `migrations/012_finding_immutability_trigger.up.sql`

- [ ] `001_create_schemas.up.sql` — Create all 12 schemas (the `reports`, `cicd`, and `evidence` schemas are created now but have no tables until later phases — this is intentional forward-provisioning)
- [ ] `002_core_tables.up.sql` — Organizations, teams, users, team_memberships, projects, scan_targets. Add `core.target_verifications` table:
  ```sql
  CREATE TABLE core.target_verifications (
      id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      target_id       UUID NOT NULL REFERENCES core.scan_targets(id),
      method          TEXT NOT NULL CHECK (method IN ('dns_txt', 'http_wellknown', 'admin_approval')),
      status          TEXT NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'verified', 'expired', 'failed')),
      token           TEXT NOT NULL,
      verified_at     TIMESTAMPTZ,
      verified_by     UUID REFERENCES core.users(id),
      expires_at      TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '90 days'),
      justification   TEXT,                   -- required for admin_approval
      created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
  );
  ```
  Also add `password_hash TEXT` to `core.users` for local auth.
- [ ] `003_scans_tables.up.sql` — scan_jobs, scan_schedules
- [ ] `004_findings_tables.up.sql` — findings (with `evidence_hash TEXT`, `evidence_size BIGINT`), finding_state_transitions, finding_annotations
- [ ] `005_vuln_intel_tables.up.sql` — vulnerabilities, package_vulnerabilities, feed_sync_status
- [ ] `006_audit_tables.up.sql` — audit_log (partitioned, with `hmac_key_version INTEGER`) + monthly partition function
- [ ] `007_rules_tables.up.sql` — rule_sets, rules
- [ ] `008_policies_tables.up.sql` — policy_definitions, policy_assignments
- [ ] `009_updates_tables.up.sql` — signing_key_certificates, revocation_entries, update_history (with verification_chain JSONB), trust_events, trust_state
- [ ] `010_auth_tables.up.sql` — auth_configs
- [ ] `011_rls_policies.up.sql` — RLS on findings, scans, projects. Session variable setup:
  ```sql
  ALTER TABLE findings.findings ENABLE ROW LEVEL SECURITY;
  CREATE POLICY findings_team_access ON findings.findings
      USING (
          project_id IN (
              SELECT p.id FROM core.projects p
              JOIN core.team_memberships tm ON tm.team_id = p.team_id
              WHERE tm.user_id = current_setting('app.current_user_id')::UUID
          )
      );

  ALTER TABLE scans.scan_jobs ENABLE ROW LEVEL SECURITY;
  CREATE POLICY scans_team_access ON scans.scan_jobs
      USING (
          project_id IN (
              SELECT p.id FROM core.projects p
              JOIN core.team_memberships tm ON tm.team_id = p.team_id
              WHERE tm.user_id = current_setting('app.current_user_id')::UUID
          )
      );

  ALTER TABLE core.projects ENABLE ROW LEVEL SECURITY;
  CREATE POLICY projects_team_access ON core.projects
      USING (
          team_id IN (
              SELECT tm.team_id FROM core.team_memberships tm
              WHERE tm.user_id = current_setting('app.current_user_id')::UUID
          )
      );
  ```
- [ ] `012_finding_immutability_trigger.up.sql`:
  ```sql
  CREATE OR REPLACE FUNCTION findings.prevent_core_field_update()
  RETURNS TRIGGER AS $$
  BEGIN
      IF OLD.title IS DISTINCT FROM NEW.title
         OR OLD.description IS DISTINCT FROM NEW.description
         OR OLD.severity IS DISTINCT FROM NEW.severity
         OR OLD.cwe_id IS DISTINCT FROM NEW.cwe_id
         OR OLD.file_path IS DISTINCT FROM NEW.file_path
         OR OLD.url IS DISTINCT FROM NEW.url
         OR OLD.code_snippet IS DISTINCT FROM NEW.code_snippet
         OR OLD.evidence_ref IS DISTINCT FROM NEW.evidence_ref
         OR OLD.evidence_hash IS DISTINCT FROM NEW.evidence_hash
         OR OLD.fingerprint IS DISTINCT FROM NEW.fingerprint
         OR OLD.finding_type IS DISTINCT FROM NEW.finding_type
         OR OLD.scan_job_id IS DISTINCT FROM NEW.scan_job_id
      THEN
          RAISE EXCEPTION 'Cannot modify immutable finding fields';
      END IF;
      RETURN NEW;
  END;
  $$ LANGUAGE plpgsql;

  CREATE TRIGGER findings_immutability
      BEFORE UPDATE ON findings.findings
      FOR EACH ROW EXECUTE FUNCTION findings.prevent_core_field_update();
  ```
- [ ] Create corresponding `.down.sql` files for each migration
- [ ] `make migrate-up` runs all migrations successfully
- [ ] Commit: `feat: add Phase 1 database schema migrations`

**Tests:**
- `make migrate-up` succeeds, `make migrate-down` rolls back cleanly
- `\dt core.*` shows all core tables
- INSERT a finding, attempt UPDATE on `title` → exception raised
- INSERT a finding, UPDATE on `status` → succeeds

---

## Milestone 3: Shared Libraries (`pkg/*`)

**Goal:** All foundation packages built with tests. Every service imports these.

### Task 3.1: `pkg/config` — Configuration loader

**Files:** Create `pkg/config/loader.go`, `pkg/config/loader_test.go`

- [ ] Implement layered config: struct defaults → env vars → optional YAML file
- [ ] Support `SENTINELCORE_` prefix for env vars (e.g., `SENTINELCORE_DB_HOST`)
- [ ] Test: defaults work, env override works, unknown env ignored
- [ ] Commit: `feat(pkg/config): add layered configuration loader`

### Task 3.2: `pkg/db` — Database connection pool and RLS

**Files:** Create `pkg/db/pool.go`, `pkg/db/migrate.go`, `pkg/db/rls.go`, `pkg/db/pool_test.go`

- [ ] `pool.go`: Open connection pool with pgx. Configure pool size, timeouts. Return `*pgxpool.Pool`.
- [ ] `migrate.go`: Wrap golang-migrate. Run migrations up/down from embedded or file path.
- [ ] `rls.go`: `SetRLSContext(ctx, pool, userID, orgID)` — sets `app.current_user_id` and `app.current_org_id` session variables on a connection. Returns `pgx.Tx` or scoped connection.
- [ ] Test with `testutil.NewTestDB()`: create DB, migrate, insert data as user A, query as user B via RLS, assert zero rows.
- [ ] Commit: `feat(pkg/db): add connection pool, migration runner, RLS helpers`

### Task 3.3: `pkg/nats` — JetStream client with message signing

**Files:** Create `pkg/nats/client.go`, `pkg/nats/consumer.go`, `pkg/nats/producer.go`, `pkg/nats/signing.go`, `pkg/nats/client_test.go`

- [ ] `client.go`: Connect to NATS, enable JetStream. Create streams (SCANS, FINDINGS, AUDIT, VULN) if not exist.
- [ ] `consumer.go`: Durable pull consumer helper with batch fetch and ack.
- [ ] `producer.go`: Publish with retry (3 attempts, exponential backoff).
- [ ] `signing.go`: HMAC-SHA256 message signing. `SignMessage(key, payload) → (payload, signature)`. `VerifyMessage(key, payload, signature) → bool`. Key derived from service identity (env var `SENTINELCORE_MSG_SIGNING_KEY`).
- [ ] Test: publish → consume round-trip. Sign → verify. Tampered message → reject.
- [ ] Commit: `feat(pkg/nats): add JetStream client with message signing`

### Task 3.4: `pkg/auth` — JWT and password management

**Files:** Create `pkg/auth/jwt.go`, `pkg/auth/session.go`, `pkg/auth/middleware.go`, `pkg/auth/password.go`, `pkg/auth/jwt_test.go`

- [ ] `jwt.go`: Issue JWT (RS256) with claims `{sub, org_id, role, exp, iat, jti}`. Validate JWT, extract claims. Key pair from env or file.
- [ ] `session.go`: Redis session store. `CreateSession(userID, jti, ttl)`. `RevokeSession(jti)`. `IsRevoked(jti) → bool`. Access token TTL: 15 min. Refresh token TTL: 8 hours.
- [ ] `middleware.go`: HTTP middleware: extract `Authorization: Bearer`, validate JWT, check session not revoked, set user context. gRPC unary interceptor: same logic.
- [ ] `password.go`: `HashPassword(plain) → hash`. `VerifyPassword(hash, plain) → bool`. bcrypt cost 12.
- [ ] Tests: issue → validate → extract claims. Expired token rejected. Revoked session rejected. Password hash round-trip.
- [ ] Commit: `feat(pkg/auth): add JWT, session management, password hashing`

### Task 3.5: `pkg/audit` — Audit event emitter

**Files:** Create `pkg/audit/emitter.go`, `pkg/audit/types.go`, `pkg/audit/emitter_test.go`

- [ ] `types.go`: `AuditEvent` struct matching the schema from Section 8.3.2 of the architecture:
  ```go
  type AuditEvent struct {
      EventID      string    `json:"event_id"`
      Timestamp    time.Time `json:"timestamp"`
      ActorType    string    `json:"actor_type"`    // user, service, system, cicd
      ActorID      string    `json:"actor_id"`
      ActorIP      string    `json:"actor_ip,omitempty"`
      Action       string    `json:"action"`        // e.g. "scan.created"
      ResourceType string    `json:"resource_type"` // e.g. "scan_job"
      ResourceID   string    `json:"resource_id"`
      OrgID        string    `json:"org_id,omitempty"`
      TeamID       string    `json:"team_id,omitempty"`
      ProjectID    string    `json:"project_id,omitempty"`
      Details      any       `json:"details,omitempty"`
      Result       string    `json:"result"`        // success, failure, denied
  }
  ```
- [ ] `emitter.go`: `Emit(ctx, event)` — publishes JSON-serialized AuditEvent to NATS `audit.events` subject. Includes `request_id` and `trace_id` from context if available.
- [ ] Test: emit event → verify NATS message received with correct structure.
- [ ] Commit: `feat(pkg/audit): add audit event emitter`

### Task 3.6: `pkg/crypto` — Canonical JSON, Ed25519, SHA-256

**Files:** Create `pkg/crypto/canonical.go`, `pkg/crypto/ed25519.go`, `pkg/crypto/sha256.go`, `pkg/crypto/canonical_test.go`, `pkg/crypto/ed25519_test.go`

- [ ] `canonical.go`: `Canonicalize(v any) ([]byte, error)` — Marshal to JSON with sorted keys, no whitespace, UTF-8. Uses `encoding/json` with sorted map keys (Go maps iterate randomly, so marshal to `map[string]any`, sort keys recursively, then serialize).
- [ ] `ed25519.go`: `Verify(publicKey, message, signature) → bool`. `Sign(privateKey, message) → signature`. Both operate on raw bytes (no pre-hashing). Thin wrapper around `crypto/ed25519`.
- [ ] `sha256.go`: `HashFile(path) → (hex string, size int64, error)`. `HashBytes(data) → hex string`.
- [ ] `canonical_test.go`: Golden test vectors:
  ```go
  // Input: {"b":2,"a":1} → Output: {"a":1,"b":2}
  // Input: {"z":{"b":2,"a":1}} → Output: {"z":{"a":1,"b":2}}
  // Input: {"a":"café"} → Output: {"a":"café"} (UTF-8 preserved)
  // Input: {} → Output: {}
  // Input: {"a":[3,1,2]} → Output: {"a":[3,1,2]} (arrays NOT sorted)
  ```
- [ ] `ed25519_test.go`: Generate keypair → sign → verify → pass. Tamper signature → reject. Wrong key → reject.
- [ ] Commit: `feat(pkg/crypto): add canonical JSON, Ed25519, SHA-256`

### Task 3.7: `pkg/ratelimit` — Redis-backed token bucket

**Files:** Create `pkg/ratelimit/limiter.go`, `pkg/ratelimit/middleware.go`, `pkg/ratelimit/limiter_test.go`

- [ ] `limiter.go`: Token bucket via Redis. `Allow(key, limit, window) → (allowed bool, remaining int, resetAt time.Time)`. Uses Redis `INCR` + `EXPIRE` for sliding window. Keys: `ratelimit:{scope}:{identifier}` (e.g., `ratelimit:user:uuid`, `ratelimit:apikey:key`).
- [ ] `middleware.go`: HTTP middleware. Extract user ID from JWT context. Apply per-user limit (100 req/min default). Return `429 Too Many Requests` with `Retry-After` header when exceeded.
- [ ] Test with real Redis: 100 requests pass, 101st is rejected. Different users have independent counters.
- [ ] Commit: `feat(pkg/ratelimit): add Redis-backed rate limiter`

### Task 3.8: `pkg/observability` and `pkg/testutil`

**Files:** Create `pkg/observability/logger.go`, `pkg/observability/metrics.go`, `pkg/observability/health.go`, `pkg/testutil/db.go`, `pkg/testutil/nats.go`, `pkg/testutil/fixtures.go`

- [ ] `logger.go`: zerolog-based. JSON output. Fields: `timestamp`, `level`, `service`, `version`. `NewLogger(serviceName) → zerolog.Logger`.
- [ ] `metrics.go`: Prometheus HTTP handler on `/metrics`. `NewMetricsServer(port)`.
- [ ] `health.go`: HTTP handler on `/healthz` returning `{"status":"ok"}`.
- [ ] `testutil/db.go`: `NewTestDB(t) → *pgxpool.Pool` — creates temporary PostgreSQL database (uses Docker or existing instance), runs migrations, returns pool. Cleanup on `t.Cleanup()`.
- [ ] `testutil/nats.go`: `NewTestNATS(t) → *nats.Conn` — starts in-process NATS server with JetStream, returns connection.
- [ ] `testutil/fixtures.go`: `CreateTestOrg(pool) → org`. `CreateTestUser(pool, orgID) → user`. `CreateTestProject(pool, orgID, teamID) → project`.
- [ ] Commit: `feat(pkg): add observability, testutil packages`

**Milestone 3 Verification:**
```bash
go test ./pkg/... -race -count=1 -v
# All pass. No external services needed except Docker for testutil/db.
```

---

## Milestone 4: RBAC and Policy Engine

**Goal:** Policy Engine service evaluates role-permission checks. Hardcoded 4-role matrix.

### Task 4.1: Define RBAC permission matrix

**Files:** Create `internal/policy/rbac.go`, `internal/policy/rbac_test.go`

- [ ] Define the 4 Phase 1 roles and their permissions:
  **Note on role naming:** Phase 1 uses 4 simplified roles. These map to the RBAC spec (Section 9) as follows and will be reconciled when the full 9-role matrix is implemented in a later phase:
  - `platform_admin` → spec's `platform_admin` (unchanged)
  - `security_admin` → consolidates spec's `security_director` + `team_admin` + `security_lead`
  - `appsec_analyst` → consolidates spec's `analyst` + `developer`
  - `auditor` → spec's `auditor` (unchanged)

  The `viewer` role from the spec is not implemented in Phase 1 (read-only access is handled by `auditor`).

  ```go
  var PermissionMatrix = map[string]map[string]bool{
      "platform_admin": {
          "users.create": true, "users.read": true, "users.update": true, "users.delete": true,
          "orgs.create": true, "orgs.read": true, "orgs.update": true,
          "teams.create": true, "teams.read": true, "teams.update": true,
          "projects.create": true, "projects.read": true, "projects.update": true, "projects.delete": true,
          "scans.create": true, "scans.read": true, "scans.cancel": true,
          "findings.read": true, "findings.triage": true,
          "targets.create": true, "targets.read": true, "targets.verify": true, "targets.approve": true,
          "audit.read": true,
          "updates.import": true, "updates.trust": true,
          "system.config": true,
      },
      "security_admin": {
          "projects.create": true, "projects.read": true, "projects.update": true,
          "scans.create": true, "scans.read": true, "scans.cancel": true,
          "findings.read": true, "findings.triage": true,
          "targets.create": true, "targets.read": true, "targets.verify": true,
          "audit.read": true,
      },
      "appsec_analyst": {
          "projects.read": true,
          "scans.create": true, "scans.read": true,
          "findings.read": true, "findings.triage": true,
          "targets.read": true,
      },
      "auditor": {
          "projects.read": true,
          "scans.read": true,
          "findings.read": true,
          "audit.read": true,
      },
  }
  ```
- [ ] `Evaluate(role, permission) → bool`
- [ ] Test: platform_admin has all permissions. auditor cannot create scans. Unknown role → deny.
- [ ] Commit: `feat(policy): add RBAC permission matrix`

### Task 4.2: Policy Engine gRPC service

**Files:** Create `api/proto/policy/v1/policy.proto`, `internal/policy/service.go`, `cmd/policy-engine/main.go`

- [ ] Define protobuf:
  ```protobuf
  service PolicyEngine {
    rpc Evaluate(EvaluateRequest) returns (EvaluateResponse);
    rpc EvaluateScanScope(ScanScopeRequest) returns (ScanScopeResponse);
  }
  message EvaluateRequest {
    string actor_role = 1;
    string permission = 2;
  }
  message EvaluateResponse {
    bool allowed = 1;
    string reason = 2;
  }
  ```
- [ ] `service.go`: gRPC server implementing PolicyEngine. Uses `rbac.go` for evaluation. Emits audit event on every evaluation.
- [ ] `scope.go`: `EvaluateScanScope` — verifies scan target has `verified_at` not null and not expired.
- [ ] `main.go`: Start gRPC server on `:9006`, metrics on `:9090`.
- [ ] Test: gRPC call with `platform_admin` + `users.create` → allowed. `auditor` + `users.create` → denied.
- [ ] Commit: `feat(policy-engine): add gRPC policy evaluation service`

**Milestone 4 Verification:**
```bash
go test ./internal/policy/... -race -v
# policy_admin → users.create: allowed
# auditor → users.create: denied
# unknown_role → anything: denied
```

---

## Milestone 5: Audit Log Service

**Goal:** All audit events from NATS are persisted to PostgreSQL append-only.

### Task 5.1: Audit log NATS consumer and PostgreSQL writer

**Files:** Create `internal/audit/consumer.go`, `internal/audit/writer.go`, `cmd/audit-service/main.go`

- [ ] `consumer.go`: Durable NATS consumer on `audit.events`. Batches messages (up to 100 or 1 second). Passes batch to writer.
- [ ] `writer.go`: Batch INSERT into `audit.audit_log`. Uses a dedicated PostgreSQL user with INSERT-only permissions (no UPDATE, no DELETE). Assigns sequential `previous_hash` (empty string for MVP; HMAC chain in Phase 5).
- [ ] `main.go`: Start consumer, metrics server on `:9090`, health check.
- [ ] Test: publish 10 audit events to NATS → query `audit.audit_log` → assert 10 rows with correct fields.
- [ ] Commit: `feat(audit-service): add NATS consumer with PostgreSQL writer`

**Milestone 5 Verification:**
```bash
# Start audit service, publish event via nats-cli:
nats pub audit.events '{"event_id":"test","timestamp":"2026-03-14T00:00:00Z","actor_type":"user","actor_id":"admin","action":"test.event","resource_type":"test","resource_id":"1","result":"success"}'
# Query DB: SELECT * FROM audit.audit_log WHERE action = 'test.event';
# → 1 row returned
```

---

## Milestone 6: Control Plane API

**Goal:** REST API for auth, CRUD operations, and scan lifecycle. Rate-limited. Audit-logged. RBAC-enforced.

### Task 6.1: HTTP server with middleware chain

**Files:** Create `internal/controlplane/server.go`, `cmd/controlplane/main.go`

- [ ] `server.go`: HTTP server using `net/http` + `gorilla/mux` (or `chi`). Middleware chain:
  1. Request ID injection
  2. Structured logging
  3. Rate limiting (`pkg/ratelimit`)
  4. JWT auth extraction (`pkg/auth/middleware`)
  5. RBAC check (gRPC call to Policy Engine)
  6. Audit event emission (`pkg/audit`)
- [ ] `main.go`: Start HTTP on `:8080`, gRPC on `:9000`, metrics on `:9090`.
- [ ] Test: `/healthz` returns 200. Unauthenticated request → 401. Rate limit exceeded → 429.
- [ ] Commit: `feat(controlplane): add HTTP server with middleware chain`

### Task 6.2: Auth endpoints

**Files:** Create `internal/controlplane/api/auth.go`

- [ ] `POST /api/v1/auth/login` — Accept `{email, password}`, verify against `core.users`, issue JWT + refresh token. Return `{access_token, refresh_token, expires_in}`.
- [ ] `POST /api/v1/auth/refresh` — Accept `{refresh_token}`, validate, issue new access token.
- [ ] `POST /api/v1/auth/logout` — Revoke session in Redis.
- [ ] Test: login with correct creds → 200 + valid JWT. Wrong password → 401. Refresh → new token. Logout → session revoked.
- [ ] Commit: `feat(controlplane): add auth endpoints`

### Task 6.3: Organization, team, user CRUD

**Files:** Create `internal/controlplane/api/organizations.go`, `api/teams.go`, `api/users.go`, `internal/controlplane/service/user_service.go`

- [ ] Org CRUD: `GET/POST /api/v1/organizations`, `GET/PATCH /api/v1/organizations/{id}`
- [ ] Team CRUD: `GET/POST /api/v1/organizations/{org_id}/teams`, team membership management
- [ ] User CRUD: `GET/POST /api/v1/users` (platform_admin only), `GET /api/v1/users/me`
- [ ] All endpoints: RBAC-checked, audit-logged
- [ ] Test: create org → create team → add user to team → query user → assert membership
- [ ] Commit: `feat(controlplane): add org, team, user CRUD`

### Task 6.4: Project and scan target CRUD

**Files:** Create `internal/controlplane/api/projects.go`, `api/scan_targets.go`, `internal/controlplane/service/project_service.go`

- [ ] Project CRUD: `GET/POST /api/v1/projects`, `GET/PATCH /api/v1/projects/{id}`
- [ ] Scan target CRUD: `GET/POST /api/v1/projects/{id}/scan-targets`
- [ ] RLS enforced: user sees only projects belonging to their teams
- [ ] Test: user A creates project in team A, user B (team B) queries projects → zero results
- [ ] Commit: `feat(controlplane): add project and scan target CRUD with RLS`

### Task 6.5: Scan lifecycle and findings API

**Files:** Create `internal/controlplane/api/scans.go`, `api/findings.go`, `internal/controlplane/service/scan_service.go`, `service/finding_service.go`

- [ ] `POST /api/v1/projects/{id}/scans` — Create scan job, validate scope via Policy Engine, publish to NATS `scan.sast.dispatch` or `scan.dast.dispatch`. Return scan ID.
- [ ] `GET /api/v1/scans/{id}` — Return scan status, progress.
- [ ] `GET /api/v1/findings?project_id=&severity=&status=` — Query findings with filters. RLS-enforced. Paginated.
- [ ] `PATCH /api/v1/findings/{id}/status` — Update finding status (mutable field). Creates state transition record.
- [ ] Test: create scan → check status=pending. Query findings with severity filter. Update finding status → verify state transition recorded.
- [ ] Commit: `feat(controlplane): add scan lifecycle and findings API`

### Task 6.6: Bootstrap CLI

**Files:** Create `internal/cli/bootstrap.go`, `cmd/cli/main.go`

- [ ] `sentinelcore-cli bootstrap --admin-email <email> --admin-password <pass>` — Creates default org, team, and the first `platform_admin` user. Writes bootstrap status to `updates.trust_state`.
- [ ] Refuses to run if bootstrap already completed (idempotent check).
- [ ] Test: run bootstrap → login with created admin → succeeds. Run again → "already bootstrapped".
- [ ] Commit: `feat(cli): add bootstrap command`

**Milestone 6 Verification:**
```bash
# Start all services, then:
sentinelcore-cli bootstrap --admin-email admin@local --admin-password changeme

curl -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@local","password":"changeme"}'
# → {"access_token":"eyJ...","refresh_token":"...","expires_in":900}

TOKEN=<access_token>
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/projects
# → {"projects":[],"total":0}

curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  http://localhost:8080/api/v1/projects \
  -d '{"name":"test-app","display_name":"Test App","team_id":"..."}'
# → {"id":"uuid","name":"test-app",...}
```

---

## Milestone 7: Worker Framework + Minimal SAST Worker

**Goal:** A SAST worker subscribes to NATS, picks up scan jobs, runs minimal pattern matching, and writes findings back.

### Task 7.1: Worker framework

**Files:** Create `internal/sast/worker.go`

- [ ] NATS durable consumer on `scan.sast.dispatch` (queue group `sast-workers` for load distribution)
- [ ] On message received:
  1. Parse scan job payload (project_id, scan_job_id, source_ref with repo_url + branch)
  2. Update scan status → `running` (via NATS publish to `scan.status.update`)
  3. Run analysis pipeline
  4. Publish findings to `scan.results.sast` (one message per finding, HMAC-signed)
  5. Update scan status → `completed` or `failed`
- [ ] Heartbeat: publish to `scan.progress` every 30 seconds with `{scan_id, phase, percent}`
- [ ] Failure handling: on panic/error, set status to `failed` with error message. Retry up to `max_retries` (re-enqueue).
- [ ] Timeout: worker-side timer matching `timeout_seconds`. Self-terminates if exceeded.
- [ ] Commit: `feat(sast): add worker framework with NATS lifecycle`

### Task 7.2: Minimal SAST analyzer

**Files:** Create `internal/sast/analyzer.go`, `internal/sast/rules.go`, `internal/sast/evidence.go`, `rules/builtin/sast-patterns.json`

- [ ] `rules.go`: Load rules from `sast-patterns.json`. Rule format:
  ```json
  [
    {
      "id": "SQLI-001",
      "title": "Potential SQL Injection",
      "cwe_id": 89,
      "severity": "high",
      "confidence": "medium",
      "languages": ["java", "python"],
      "pattern": "(?i)(execute|executeQuery|executeUpdate)\\s*\\(.*\\+.*\\)",
      "description": "String concatenation in SQL query execution"
    }
  ]
  ```
- [ ] Provide minimum 20 patterns covering: SQL injection, XSS, command injection, path traversal, hardcoded secrets (regex + entropy).
- [ ] `analyzer.go`: For each file in the source directory:
  1. Detect language by extension
  2. Apply matching rules (regex-based for MVP)
  3. Generate finding with: fingerprint (SHA-256 of file_path + line + rule_id), code snippet (3 lines context), evidence metadata
- [ ] `evidence.go`: Package code snippet as JSON, compute SHA-256 hash, upload to MinIO at `evidence/{project_id}/{scan_id}/sast/{finding_id}/snippet.json`. Return `evidence_ref` path and `evidence_hash`.
- [ ] Test: run analyzer on a test Java file containing `stmt.executeQuery("SELECT * FROM users WHERE id=" + id)` → produces finding with CWE-89, severity high.
- [ ] Commit: `feat(sast): add minimal pattern-matching analyzer with evidence upload`

### Task 7.3: SAST worker entry point

**Files:** Create `cmd/sast-worker/main.go`

- [ ] Connect to NATS, MinIO, load rules
- [ ] For MVP: worker receives `source_ref.repo_url`, does `git clone --depth=1`, runs analyzer on cloned directory, cleans up
- [ ] All findings signed with message HMAC before publishing
- [ ] `main.go`: start worker, metrics on `:9090`
- [ ] Integration test: publish scan job to NATS → worker picks up → findings appear in `scan.results.sast` → verify HMAC signature
- [ ] Commit: `feat(sast-worker): add entry point with git clone and analysis pipeline`

**Milestone 7 Verification:**
```bash
# Publish a scan job to NATS:
nats pub scan.sast.dispatch '{"scan_job_id":"uuid","project_id":"uuid","source_ref":{"repo_url":"https://github.com/example/vuln-app","branch":"main"}}'

# Worker logs show: cloning, analyzing, N findings produced
# Check NATS for findings: nats sub 'scan.results.sast' (should see finding messages)
# Check MinIO: mc ls minio/evidence/ (should see evidence files)
```

---

## Milestone 8: Vulnerability Intelligence Ingestion

**Goal:** Import vulnerability data from NVD, OSV, and GitHub Advisory into a unified schema. Support both online fetch and offline signed bundle import.

### Task 8.1: Vulnerability feed parsers

**Files:** Create `internal/vuln/ingest/nvd.go`, `internal/vuln/ingest/osv.go`, `internal/vuln/ingest/github.go`, `internal/vuln/ingest/nvd_test.go`

- [ ] `nvd.go`: Parse NVD JSON 2.0 format (CVE items). Extract: CVE ID, title, description, CVSS v3.1 score + vector, CWE IDs, affected CPE entries, references, published/modified dates.
- [ ] `osv.go`: Parse OSV JSON format. Extract: ID (GHSA/PYSEC/etc), summary, affected packages (ecosystem + name + version ranges), severity, references.
- [ ] `github.go`: Parse GitHub Advisory Database JSON. Extract: GHSA ID, CVE ID, summary, severity, affected packages with version ranges, fixed versions.
- [ ] `nvd_test.go`: Parse a real NVD JSON sample (embed as test fixture). Assert correct CVE ID, CVSS, CWE extraction.
- [ ] Commit: `feat(vuln): add NVD, OSV, GitHub Advisory parsers`

### Task 8.2: Normalizer and package-to-CVE matcher

**Files:** Create `internal/vuln/normalizer.go`, `internal/vuln/matcher.go`

- [ ] `normalizer.go`: Convert parsed feed data to unified internal schema (`vuln_intel.vulnerabilities` + `vuln_intel.package_vulnerabilities`). Dedup key: CVE ID. Source priority: NVD (CVSS) > GitHub (package mapping) > OSV (supplementary).
- [ ] `matcher.go`: `MatchPackage(ecosystem, name, version) → []Vulnerability`. Parse version ranges per ecosystem:
  - npm: semver ranges (`>=1.0.0 <2.0.0`)
  - PyPI: PEP 440 (`>=1.0,<2.0`)
  - Maven: Maven version ranges (`[1.0,2.0)`)
  - Go: Go module pseudo-versions
- [ ] Test: match `lodash@4.17.20` against known CVE → returns CVE-2021-23337. Non-affected version → returns empty.
- [ ] Commit: `feat(vuln): add normalizer and package matcher`

### Task 8.3: Vuln Intel gRPC service and offline import

**Files:** Create `internal/vuln/service.go`, `internal/vuln/offline.go`, `cmd/vuln-intel/main.go`

- [ ] `service.go`: gRPC server implementing:
  - `LookupByPackage(ecosystem, name, version) → []Vulnerability`
  - `LookupByCVE(cve_id) → Vulnerability`
  - `GetFeedStatus() → []FeedSyncStatus`
  - `ImportBundle(path) → ImportResult`
- [ ] `offline.go`: Import signed bundle (trust chain verified by calling Update Manager). Parse each feed file, run through normalizer, batch INSERT into PostgreSQL. Update `feed_sync_status`.
- [ ] `main.go`: Start gRPC on `:9003`, metrics on `:9090`.
- [ ] Test: import NVD test fixture → query by CVE ID → returns correct vulnerability. Query by package → returns matching CVEs.
- [ ] Commit: `feat(vuln-intel): add gRPC service with offline bundle import`

**Milestone 8 Verification:**
```bash
# Import test NVD data:
sentinelcore-cli vuln import --bundle test/fixtures/nvd-sample.json

# Query via gRPC:
grpcurl -plaintext localhost:9003 vuln.v1.VulnIntel/LookupByCVE '{"cve_id":"CVE-2021-44228"}'
# → Returns Log4Shell vulnerability details
```

---

## Milestone 9: Secure Update Verification

**Goal:** Update Manager implements the full 25-step trust chain verification from the trust architecture spec.

### Task 9.1: Trust store and lockdown management

**Files:** Create `internal/updater/trust.go`, `internal/updater/lockdown.go`

- [ ] `trust.go`:
  - Read/write root public key from `/var/lib/sentinelcore/trust/root_pubkey.json` (or configurable path)
  - Read/write signing key certificates to `updates.signing_key_certificates` table
  - Read/write revocation list from file + `updates.revocation_entries` table
  - `GetTrustState() → TrustState` (read from `updates.trust_state`)
  - Startup self-check: verify root_pubkey.json hash matches value in database
- [ ] `lockdown.go`:
  - `IsLockdownActive() → bool` — reads from `updates.trust_state` table (key=`lockdown`)
  - `EnableLockdown(reason) → error` — sets lockdown=true in DB, logs trust event
  - `DisableLockdown() → error` — sets lockdown=false in DB, logs trust event
- [ ] Test: set lockdown → `IsLockdownActive()` returns true. Disable → false. Trust state round-trip.
- [ ] Commit: `feat(updater): add trust store and lockdown management`

### Task 9.2: 25-step bundle verification

**Files:** Create `internal/updater/verify.go`, `internal/updater/verify_test.go`

- [ ] Implement each verification step as a separate, testable function:
  ```go
  func (v *Verifier) ExtractBundle(bundlePath, quarantineDir string) error           // Step 1
  func (v *Verifier) ReadMetadataFiles(quarantineDir string) (*BundleMetadata, error) // Step 2
  func (v *Verifier) VerifyRevocationSignature(revocations, sig []byte, rootKey ed25519.PublicKey) error // Step 3
  func (v *Verifier) UpdateLocalRevocations(bundleRevocations *RevocationList) error  // Step 4-5
  func (v *Verifier) VerifySigningCertSignature(cert, sig []byte, rootKey ed25519.PublicKey) error // Step 6
  func (v *Verifier) VerifyRootFingerprint(cert *SigningKeyCert, rootKey ed25519.PublicKey) error // Step 7
  func (v *Verifier) CheckCertNotRevoked(serial string) error                        // Step 8
  func (v *Verifier) CheckCertValidity(cert *SigningKeyCert, now time.Time) error    // Step 9-10 (48h grace)
  func (v *Verifier) CheckCertPurpose(cert *SigningKeyCert, bundleType string) error // Step 11
  func (v *Verifier) VerifyManifestSignature(manifest, sig []byte, signingKey ed25519.PublicKey) error // Step 15-16
  func (v *Verifier) VerifyManifestCertSerial(manifest *Manifest, cert *SigningKeyCert) error // Step 14
  func (v *Verifier) VerifyArtifactHashes(quarantineDir string, manifest *Manifest) error // Step 18
  func (v *Verifier) CheckNoExtraFiles(quarantineDir string, manifest *Manifest) error // Step 19
  func (v *Verifier) CheckVersionMonotonicity(manifest *Manifest) error               // Step 20
  func (v *Verifier) CheckCompatibility(manifest *Manifest) error                     // Step 21-22

  // Orchestrator:
  func (v *Verifier) VerifyBundle(bundlePath string) (*VerificationResult, error)     // Steps 1-25
  ```
- [ ] `verify_test.go`: **Each step gets its own test:**
  - Valid bundle → all steps pass → VerificationResult.Accepted = true
  - Tampered manifest signature → Step 16 fails
  - Revoked certificate → Step 8 fails
  - Expired certificate → Step 10 fails
  - Wrong purpose (rule cert for platform bundle) → Step 11 fails
  - Tampered artifact hash → Step 18 fails
  - Version downgrade → Step 20 fails
  - Lockdown active → rejected before Step 1
- [ ] Commit: `feat(updater): implement 25-step bundle verification`

### Task 9.3: Update Manager gRPC service and CLI

**Files:** Create `internal/updater/service.go`, `cmd/updater/main.go`, `internal/cli/update.go`

- [ ] `service.go`: gRPC server:
  - `ImportBundle(path) → ImportResult` — runs full verification, stages if valid, records in `updates.update_history`
  - `GetTrustState() → TrustState`
  - `ListSigningCertificates() → []Certificate`
  - `EnableLockdown(reason) → Result`
  - `DisableLockdown() → Result`
- [ ] `main.go`: Start gRPC on `:9009`, metrics on `:9090`.
- [ ] CLI commands:
  - `sentinelcore-cli update verify-bundle --bundle <path>` — dry-run verification
  - `sentinelcore-cli update trust-status` — show root key fingerprint, active certs, lockdown state
  - `sentinelcore-cli update lockdown --enable/--disable`
  - `sentinelcore-cli update import --bundle <path>`
- [ ] Test: generate test keypair → sign test bundle → import via CLI → verify accepted. Tamper bundle → verify rejected.
- [ ] Commit: `feat(updater): add Update Manager gRPC service and CLI`

**Milestone 9 Verification:**
```bash
# Generate test root key and signing key for testing:
go run scripts/gen-test-keys.go  # Creates test root + signing keypair

# Create and sign a test bundle:
go run scripts/sign-test-bundle.go --root-key test-root.key --signing-key test-signing.key

# Verify:
sentinelcore-cli update verify-bundle --bundle test-bundle.tar.gz
# → "Verification PASSED: 25/25 steps OK"

# Tamper and verify again:
echo "tampered" >> test-bundle.tar.gz
sentinelcore-cli update verify-bundle --bundle test-bundle.tar.gz
# → "Verification FAILED at step 18: artifact hash mismatch"
```

---

## Milestone 10: Integration Tests and Deliverables

**Goal:** End-to-end tests proving the platform works. Docker Compose brings up everything.

### Task 10.1: Full Docker Compose with all services

**Files:** Modify `deploy/docker-compose/docker-compose.yml`

- [ ] Add service entries for: `controlplane`, `policy-engine`, `audit-service`, `sast-worker`, `vuln-intel`, `updater`
- [ ] Each service depends on infrastructure (postgres, nats, redis, minio)
- [ ] Controlplane depends on policy-engine and audit-service
- [ ] Environment variables for all connection strings
- [ ] `make docker-up` starts all 10 containers (4 infra + 6 app)
- [ ] Commit: `feat(deploy): add all Phase 1 services to Docker Compose`

### Task 10.2: Integration test suite

**Files:** Create `test/integration/auth_rbac_test.go`, `scan_pipeline_test.go`, `audit_test.go`, `vuln_intel_test.go`, `update_trust_test.go`, `ratelimit_test.go`

- [ ] `auth_rbac_test.go`:
  - Bootstrap → login as admin → create second user (appsec_analyst) → login as analyst
  - Admin can access `GET /api/v1/admin/users` → 200
  - Analyst cannot access `GET /api/v1/admin/users` → 403
  - Create project in team A, user from team B queries projects → zero results (RLS)
- [ ] `scan_pipeline_test.go`:
  - Create project → create scan target → trigger SAST scan → poll status until completed
  - Query findings → assert at least one finding with correct fields (severity, CWE, evidence_ref)
  - Verify evidence_hash in finding matches SHA-256 of evidence in MinIO
  - Verify all operations appear in audit log
- [ ] `audit_test.go`:
  - Perform 5 distinct operations (create org, create project, create scan, etc.)
  - Query audit log → assert 5 events with correct action names and actor IDs
  - Verify audit events have sequential IDs (no gaps)
- [ ] `vuln_intel_test.go`:
  - Import NVD test fixture
  - Query by CVE ID → returns correct vulnerability
  - Query by package (lodash@4.17.20, ecosystem=npm) → returns matching CVEs
- [ ] `update_trust_test.go`:
  - Import valid signed bundle → accepted
  - Import bundle with tampered signature → rejected
  - Import bundle with revoked signing cert serial → rejected
  - Enable lockdown → import any bundle → rejected. Disable lockdown → import succeeds.
- [ ] `ratelimit_test.go`:
  - Send 100 requests in 1 minute → all pass
  - Send 101st request → 429 with Retry-After header
  - Different user → independent counter (passes)
- [ ] Commit: `test: add Phase 1 integration test suite`

### Task 10.3: Acceptance script

**Files:** Create `scripts/acceptance-test.sh`

- [ ] Script that runs against a live Docker Compose environment:
  ```bash
  #!/bin/bash
  set -euo pipefail

  BASE_URL="http://localhost:8080/api/v1"

  echo "=== Phase 1 Acceptance Test ==="

  echo "1. Bootstrap..."
  sentinelcore-cli bootstrap --admin-email admin@local --admin-password changeme

  echo "2. Login..."
  TOKEN=$(curl -sf -X POST "$BASE_URL/auth/login" \
    -H 'Content-Type: application/json' \
    -d '{"email":"admin@local","password":"changeme"}' | jq -r '.access_token')
  echo "   Token: ${TOKEN:0:20}..."

  echo "3. Create organization..."
  ORG_ID=$(curl -sf -X POST "$BASE_URL/organizations" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"name":"acme","display_name":"Acme Corp"}' | jq -r '.id')
  echo "   Org ID: $ORG_ID"

  echo "4. Create team..."
  TEAM_ID=$(curl -sf -X POST "$BASE_URL/organizations/$ORG_ID/teams" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"name":"security","display_name":"Security Team"}' | jq -r '.id')
  echo "   Team ID: $TEAM_ID"

  echo "5. Create project..."
  PROJECT_ID=$(curl -sf -X POST "$BASE_URL/projects" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"test-app\",\"display_name\":\"Test App\",\"team_id\":\"$TEAM_ID\",\"repository_url\":\"https://github.com/OWASP/WebGoat\"}" | jq -r '.id')
  echo "   Project ID: $PROJECT_ID"

  echo "6. Trigger SAST scan..."
  SCAN_ID=$(curl -sf -X POST "$BASE_URL/projects/$PROJECT_ID/scans" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"scan_type":"sast","trigger_type":"manual"}' | jq -r '.id')
  echo "   Scan ID: $SCAN_ID"

  echo "7. Wait for scan completion..."
  for i in $(seq 1 60); do
    STATUS=$(curl -sf "$BASE_URL/scans/$SCAN_ID" \
      -H "Authorization: Bearer $TOKEN" | jq -r '.status')
    if [ "$STATUS" = "completed" ]; then
      echo "   Scan completed!"
      break
    fi
    sleep 5
  done

  echo "8. Query findings..."
  FINDING_COUNT=$(curl -sf "$BASE_URL/findings?project_id=$PROJECT_ID" \
    -H "Authorization: Bearer $TOKEN" | jq '.total')
  echo "   Found $FINDING_COUNT findings"

  echo "9. Check audit log..."
  AUDIT_COUNT=$(curl -sf "$BASE_URL/admin/audit-log?limit=100" \
    -H "Authorization: Bearer $TOKEN" | jq '.total')
  echo "   $AUDIT_COUNT audit events"

  echo "10. Verify update trust..."
  sentinelcore-cli update trust-status
  echo "   Trust status displayed"

  echo "11. Test rate limiting..."
  for i in $(seq 1 105); do
    HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "$BASE_URL/projects" \
      -H "Authorization: Bearer $TOKEN" 2>/dev/null || echo "429")
    if [ "$HTTP_CODE" = "429" ]; then
      echo "   Rate limit hit at request $i ✓"
      break
    fi
  done

  echo ""
  echo "=== Phase 1 Acceptance Test PASSED ==="
  ```
- [ ] Commit: `test: add Phase 1 acceptance script`

---

## Testing Strategy Summary

| Layer | What | How | Coverage Target |
|---|---|---|---|
| Unit | `pkg/*`, `internal/*/` business logic | `go test ./pkg/... ./internal/...` | 80% business logic, 90% crypto |
| Integration | End-to-end flows against real infra | `go test ./test/integration/... -tags=integration` | All critical paths |
| Migration | Schema up/down, data integrity | `make migrate-up && make migrate-down` round-trip | All migrations reversible |
| Security: RBAC | Every role × every permission | `auth_rbac_test.go` | All 4 roles, all denied paths |
| Security: RLS | Cross-team data isolation | `auth_rbac_test.go` | Team A cannot see team B data |
| Security: Immutability | Finding core field protection | `scan_pipeline_test.go` | UPDATE on immutable field → exception |
| Security: Update trust | 25-step verification | `update_trust_test.go` | Each failure mode tested individually |
| Security: Rate limit | Excess requests blocked | `ratelimit_test.go` | 429 returned, Retry-After header present |
| Security: Message signing | Tampered messages rejected | `scan_pipeline_test.go` | Unsigned finding → rejected |
| Acceptance | Full user journey | `scripts/acceptance-test.sh` | 11 steps, all pass |

---

## Security Controls Implemented in Phase 1

| Control | Implementation | Verification |
|---|---|---|
| **RBAC** | 4-role permission matrix, Policy Engine gRPC, middleware enforcement | Integration test: auditor cannot create scans |
| **Row-Level Security** | PostgreSQL RLS policies on findings, scans, projects | Integration test: cross-team isolation |
| **Rate Limiting** | Redis-backed token bucket, HTTP middleware, 100 req/min/user | Integration test: 429 on excess |
| **Audit Logging** | NATS event bus, append-only PostgreSQL, INSERT-only DB user | Integration test: all ops logged |
| **Finding Immutability** | PostgreSQL trigger prevents UPDATE on core fields | Migration test: UPDATE title → exception |
| **Signed Messages** | HMAC-SHA256 on worker result messages | Integration test: tampered message rejected |
| **Signed Updates** | Ed25519 trust chain (root → cert → manifest → artifacts) | 8 verification failure mode tests |
| **Password Security** | bcrypt cost 12, no plaintext storage | Unit test: hash/verify round-trip |
| **JWT Sessions** | RS256, 15-min access TTL, Redis revocation | Unit test: expired/revoked tokens rejected |
| **Input Validation** | All API inputs validated before processing | Each API handler validates input |

---

## Deliverables at End of Phase 1

### Commands that must succeed:

```bash
# 1. Start the platform
make docker-up
# Starts: postgres, nats, redis, minio, controlplane, policy-engine,
#         audit-service, sast-worker, vuln-intel, updater

# 2. Bootstrap
sentinelcore-cli bootstrap --admin-email admin@local --admin-password changeme

# 3. All unit tests pass
make test

# 4. All integration tests pass
make test-integration

# 5. Acceptance test passes
./scripts/acceptance-test.sh

# 6. Verify trust chain works
sentinelcore-cli update verify-bundle --bundle test/fixtures/valid-bundle.tar.gz
# → PASSED

sentinelcore-cli update verify-bundle --bundle test/fixtures/tampered-bundle.tar.gz
# → FAILED at step 18

# 7. Clean shutdown
make docker-down
```

### Artifacts produced:
- 6 compiled Go binaries (`bin/controlplane`, `bin/policy-engine`, `bin/audit-service`, `bin/sast-worker`, `bin/vuln-intel`, `bin/updater`, `bin/cli`)
- 12+ SQL migrations (up and down)
- Docker Compose environment with 10 containers
- 20+ built-in SAST rules
- Integration test suite with 6 test files
- Acceptance test script
- gRPC proto definitions for 4 services
