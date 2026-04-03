# SentinelCore Secrets Management

## Secret Inventory

Every secret required by SentinelCore services:

| Secret | Used By | Purpose | Format |
|--------|---------|---------|--------|
| `DB_PASSWORD` | controlplane, policy-engine, audit-service, vuln-intel, updater | PostgreSQL authentication | String |
| `DATABASE_URL` | retention-worker, notification-worker | PostgreSQL connection string (contains password) | `postgres://user:pass@host:port/db` |
| `REDIS_URL` | controlplane | Redis connection (may contain password) | `redis://:password@host:port` |
| `JWT_PRIVATE_KEY_FILE` | controlplane | Signs JWT access tokens | Path to RSA PEM private key (4096-bit recommended) |
| `JWT_PUBLIC_KEY_FILE` | controlplane | Verifies JWT access tokens | Path to RSA PEM public key |
| `MSG_SIGNING_KEY` | controlplane, dast-worker, dast-browser-worker, sast-worker, correlation-engine | HMAC signature on NATS messages | Random string, minimum 32 bytes |
| `AUTH_PROFILE_ENCRYPTION_KEY` | controlplane | Encrypts stored authentication profiles (credentials for target applications) | AES-256 key, base64-encoded |
| CSRF cookie secret | controlplane | Internal; derived from session state | Managed automatically |
| `MINIO_ROOT_USER` | minio | Object storage admin user | String |
| `MINIO_ROOT_PASSWORD` | minio | Object storage admin password | String |

## Development Defaults

For local development, SentinelCore ships with defaults that allow zero-configuration startup:

| Secret | Default |
|--------|---------|
| `DB_PASSWORD` | `dev-password` |
| `MSG_SIGNING_KEY` | `dev-signing-key-change-me` |
| `JWT_PRIVATE_KEY_FILE` | Auto-generated ephemeral key pair on startup |
| `REDIS_URL` | `redis://localhost:6379` (no auth) |
| `MINIO_ROOT_USER` | `minioadmin` |
| `MINIO_ROOT_PASSWORD` | `minioadmin` |

These defaults are only suitable for development. Production deployments must override every secret.

## Production Requirements

In production, all secrets must be:

1. **Externally managed** -- never committed to source control or baked into images.
2. **Unique per environment** -- staging and production must not share secrets.
3. **Rotatable** -- every secret must be rotatable without data loss (see rotation procedures below).
4. **Audited** -- access to secrets should be logged.

### Minimum Production Secrets

```bash
# Generate JWT key pair
openssl genrsa -out /secrets/jwt.key 4096
openssl rsa -in /secrets/jwt.key -pubout -o /secrets/jwt.pub

# Generate MSG_SIGNING_KEY (32 random bytes, hex-encoded)
openssl rand -hex 32 > /secrets/msg-signing-key.txt

# Generate AUTH_PROFILE_ENCRYPTION_KEY (32 random bytes, base64)
openssl rand -base64 32 > /secrets/encryption-key.txt

# Generate DB_PASSWORD
openssl rand -base64 24 > /secrets/db-password.txt
```

## Vault Integration (Recommended)

SentinelCore does not have a native Vault client. The recommended approach is environment injection via a sidecar or init container.

### Kubernetes with Vault Agent

```yaml
# Pod annotation for Vault Agent sidecar injection
metadata:
  annotations:
    vault.hashicorp.com/agent-inject: "true"
    vault.hashicorp.com/role: "sentinelcore"
    vault.hashicorp.com/agent-inject-secret-db: "secret/data/sentinelcore/db"
    vault.hashicorp.com/agent-inject-template-db: |
      {{- with secret "secret/data/sentinelcore/db" -}}
      export DB_PASSWORD="{{ .Data.data.password }}"
      {{- end }}
```

### Docker Compose with Vault

Use an entrypoint script that reads secrets from Vault and exports them as environment variables before starting the service. Alternatively, use Docker secrets with a `secrets:` block.

### Other Secret Managers

Any system that can inject environment variables or mount files works:

- **AWS Secrets Manager**: Use the ECS/EKS secrets integration
- **GCP Secret Manager**: Use the CSI driver or workload identity
- **Azure Key Vault**: Use the CSI driver or managed identity
- **SOPS / age**: Decrypt at deploy time and inject

## Key Rotation Procedures

### JWT Keys

**Impact**: Users with tokens signed by the old key cannot authenticate after rotation. Tokens have a 15-minute TTL, so the disruption window is brief.

**Procedure**:

1. Generate a new RSA key pair:
   ```bash
   openssl genrsa -out jwt-new.key 4096
   openssl rsa -in jwt-new.key -pubout -o jwt-new.pub
   ```
2. Replace the key files referenced by `JWT_PRIVATE_KEY_FILE` and `JWT_PUBLIC_KEY_FILE`.
3. Restart the controlplane.
4. Old tokens expire within 15 minutes. Users are prompted to re-login.

No database changes are required.

### MSG_SIGNING_KEY

**Impact**: All services using this key must be updated simultaneously. Messages in flight signed with the old key will fail validation and be retried.

**Procedure**:

1. Generate a new key: `openssl rand -hex 32`
2. Update the `MSG_SIGNING_KEY` environment variable on all services: controlplane, dast-worker, dast-browser-worker, sast-worker, correlation-engine.
3. Restart all affected services at the same time.
4. Monitor NATS for rejected messages; they will be retried automatically by producers.

### DB_PASSWORD

**Impact**: Rolling restart required. Brief connection errors during transition.

**Procedure**:

1. Generate a new password: `openssl rand -base64 24`
2. Update the password in PostgreSQL:
   ```sql
   ALTER USER sentinelcore WITH PASSWORD 'new-password-here';
   ```
3. Update `DB_PASSWORD` (and `DATABASE_URL` for retention-worker and notification-worker) in the environment.
4. Perform a rolling restart of all services that connect to PostgreSQL.

### AUTH_PROFILE_ENCRYPTION_KEY

**Impact**: Stored authentication profiles are encrypted with this key. Changing it without re-encryption makes existing profiles unreadable.

**Current state**: Rotation requires a manual re-encryption migration:
1. Decrypt all profiles with the old key.
2. Re-encrypt with the new key.
3. Update the environment variable and restart.

**Future**: A `key_id` column will be added to the auth profiles table, allowing the system to support multiple active keys and decrypt with the correct key version. This will enable zero-downtime rotation.

### Redis Password

If Redis authentication is enabled:

1. Set the new password in Redis: `CONFIG SET requirepass "new-password"`
2. Update `REDIS_URL` to include the new password.
3. Restart the controlplane.

## Emergency: Key Compromise Response

### JWT Key Compromise

An attacker with the JWT private key can forge authentication tokens for any user.

**Immediate actions**:

1. **Revoke all sessions**: Flush Redis session keys to invalidate every active session:
   ```bash
   redis-cli KEYS "session:*" | xargs redis-cli DEL
   ```
2. **Rotate keys**: Generate and deploy a new JWT key pair (see procedure above).
3. **Restart** the controlplane.
4. **Notify** all users that they must re-login.
5. **Audit**: Review the audit log (`audit.audit_events`) for unauthorized actions during the compromise window.

### MSG_SIGNING_KEY Compromise

An attacker with this key can forge inter-service messages, potentially injecting false scan results.

**Immediate actions**:

1. **Rotate the key** immediately across all services (see procedure above).
2. **Restart** all workers and the controlplane.
3. **Review findings**: Examine recent scan findings for anomalies. Any finding created during the compromise window should be treated as suspect.
4. **Reprocess**: If suspicious messages were identified, re-trigger affected scans to generate clean results.

### DB_PASSWORD Compromise

An attacker with database credentials can read or modify all data.

**Immediate actions**:

1. **Rotate immediately**: Change the PostgreSQL password and update all services (see procedure above).
2. **Audit access**: Check PostgreSQL logs (`pg_stat_activity`, `log_connections`) for unauthorized connections.
3. **Review audit log**: Check `audit.audit_events` for unexpected modifications.
4. **Consider**: If data integrity is in question, restore from the last known-good backup and replay events.

### MINIO / Object Storage Credentials Compromise

**Immediate actions**:

1. Rotate MinIO root credentials or the IAM access key.
2. Audit object access logs for unauthorized reads or writes.
3. If scan artifacts were exfiltrated, assess the sensitivity of the exposed data (scan results, reports).
