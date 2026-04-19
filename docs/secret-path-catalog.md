# Secret Path Catalog

Every long-lived secret in SentinelCore is fetched through
`pkg/secrets.Resolver.Get(ctx, path)` using one of the canonical paths
below. Ad-hoc path strings are forbidden — the `paths.go` constants
exist so typos are compiler errors.

The tiering matches §3.2 of the Phase 7 plan:

- **Tier 0** — Root secrets (master keys, signing keys). Smallest
  blast radius; highest sensitivity. Rotation ceremony required.
- **Tier 1** — Service credentials (DB DSNs, Redis, NATS, SMTP).
  Rotated on a schedule or on compromise. No ceremony for routine
  rotation.
- **Tier 2** — Tenant data-at-rest (SSO client secrets, webhook
  signing keys). Encrypted with a Tier 0 AES key; path stored as an
  envelope in the DB column.
- **Tier 3** — User-controlled secrets (API keys). HMAC'd with the
  Tier 0 pepper before storage.

---

## Tier 0 — Root

| Path | Constant | Size | Consumer | Notes |
|---|---|---|---|---|
| `tier0/aes/master` | `PathAESMaster` | 32 B | envelope | Default AES purpose key. Per-purpose keys live in `auth.aes_keys` catalog. |
| `tier0/hmac/audit` | `PathHMACAudit` | 32 B | audit-service | HMAC key for audit chain signing. Catalog at `audit.hmac_keys`. |
| `tier0/apikey/pepper` | `PathAPIKeyPepper` | 32+ B | controlplane | HMAC pepper for `core.api_keys.key_verifier`. Catalog at `auth.apikey_peppers`. |
| `tier0/jwt/private` | `PathJWTPrivate` | ~1 KB | controlplane | RS256 PEM. Used to SIGN access tokens. |
| `tier0/jwt/public` | `PathJWTPublic` | ~300 B | all services | RS256 PEM. Used to VERIFY access tokens. |

All Tier 0 material MUST live in a separate trust boundary from the
app process (Vault in production; env file in dev). Loss of any Tier 0
key is an incident; see operator runbook §5.

---

## Tier 1 — Service credentials

| Path | Constant | Format | Consumer |
|---|---|---|---|
| `tier1/postgres/controlplane` | `PathPostgresControlplane` | pgx DSN | controlplane |
| `tier1/postgres/audit-worker` | `PathPostgresAuditWriter` | pgx DSN | audit-service |
| `tier1/postgres/worker` | `PathPostgresWorker` | pgx DSN | sast-worker, dast-worker, correlation-engine |
| `tier1/postgres/readonly` | `PathPostgresReadonly` | pgx DSN | sc-backup, reporting |
| `tier1/redis/auth` | `PathRedisAuth` | `user:password` | controlplane (session store) |
| `tier1/nats/nkey` | `PathNATSNkey` | nkey seed | controlplane, audit-service, workers |
| `tier1/smtp/password` | `PathSMTPPassword` | ASCII password | notification-worker |
| `tier1/backup/age-recipient` | `PathBackupAgeRecipient` | age X25519 pubkey | sc-backup |

---

## Tier 2 — Tenant data-at-rest (in-DB envelopes)

Stored IN the database as `enc:v<N>:<purpose>:<base64(ciphertext)>`
strings. The Tier 0 AES master key decrypts them; the `auth.aes_keys`
catalog row for `(version, purpose)` holds the vault_path that
resolves to the actual key bytes.

Current columns using the envelope format:

| Table.column | Purpose | Migration |
|---|---|---|
| `auth.oidc_providers.client_secret_encrypted` | `sso` | 029 |
| `auth.auth_configs.secret_encrypted` (planned) | `auth_profile` | 030 |
| `governance.webhook_configs.secret_encrypted` | `webhook` | 014 |

Adding a new envelope column:

1. Pick a purpose from the CHECK list in migration 039.
2. Add a row to this catalog and to `auth.aes_keys` if the purpose
   is new.
3. Use `pkg/crypto/envelope.Envelope.Seal(purpose, plain, aad)` at
   write time; `Open(envelope, aad)` at read time.

---

## Tier 3 — User-controlled

| Path | Storage | Protection |
|---|---|---|
| `core.api_keys.key_verifier` | HMAC-SHA256 using Tier 0 pepper | Irreversible; rotation = forced reissue |
| `core.api_keys.key_hash` (legacy) | SHA-256 (unsalted) | Kept for 90-day transition window; drop after |

---

## Path naming rules

- All lowercase, slash-delimited.
- Segments: `tier<N>/<category>/<name>` where `N` ∈ {0,1,2,3}.
- No version suffix in the PATH — versions live in the corresponding
  catalog table (`auth.aes_keys`, `audit.hmac_keys`,
  `auth.apikey_peppers`). `vault_path` there CAN have a `/v<N>` suffix.
- Only `[a-z0-9_-/]` allowed — `pkg/secrets.pathToEnvVar` enforces.

## Drift check

The constants in `pkg/secrets/paths.go` and the table above are
kept in sync by a CI check:

    go test ./pkg/secrets/ -run TestSecretPathsDriftCheck

The test fails when a path exists in one place but not the other.
When you add a path: update `paths.go`, add the row to this doc,
then run the test.
