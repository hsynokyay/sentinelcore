# API Keys

API keys let CI/CD pipelines authenticate with SentinelCore without using
user passwords. Keys are scoped, revocable, and optionally time-limited.

## Key format

Keys use the format `sc_<32-random-hex>` (e.g., `sc_a1b2c3d4e5f6...`).
The plaintext is returned exactly once at creation time and is never stored.
Only the SHA-256 hash is persisted.

## API

### Create an API key

```bash
curl -X POST https://sentinelcore.example.com/api/v1/api-keys \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "CI Pipeline", "scopes": ["findings.read", "scans.read"], "expires_in": "90d"}'
```

Response (the `key` field is shown **exactly once**):
```json
{
  "api_key": {
    "id": "...",
    "name": "CI Pipeline",
    "prefix": "sc_a1b2c3d…",
    "scopes": ["findings.read", "scans.read"],
    "expires_at": "2026-07-05T00:00:00Z",
    "created_at": "2026-04-07T00:00:00Z"
  },
  "key": "sc_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
}
```

### Use an API key

```bash
# Use the key as a Bearer token — same as JWTs.
curl -H "Authorization: Bearer sc_a1b2c3d4e5f6..." \
  https://sentinelcore.example.com/api/v1/scans/$SCAN_ID/report.sarif
```

### List API keys

```bash
curl -H "Authorization: Bearer $USER_TOKEN" \
  https://sentinelcore.example.com/api/v1/api-keys
```

### Revoke an API key

```bash
curl -X DELETE -H "Authorization: Bearer $USER_TOKEN" \
  https://sentinelcore.example.com/api/v1/api-keys/$KEY_ID
```

## Scopes

| Scope | Grants |
|---|---|
| `findings.read` | Read findings + exports |
| `scans.read` | Read scans + exports |
| `scans.create` | Create scans |
| `targets.read` | Read targets |

Default scopes (if not specified): `findings.read`, `scans.read`.

## Expiration

Use `expires_in` with day/hour units: `30d`, `90d`, `365d`, `24h`.
Keys without expiration are valid until revoked.

## Security

- Keys are hashed at rest (SHA-256). Plaintext is never stored.
- Revoked keys are rejected immediately.
- Expired keys are rejected at auth time.
- `last_used_at` is tracked for auditing.
- Creation and revocation emit audit events.
- Only `platform_admin` and `security_admin` can create/manage keys.
