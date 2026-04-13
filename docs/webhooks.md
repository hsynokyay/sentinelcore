# Webhooks

SentinelCore can notify external systems when scans complete by sending
signed webhook payloads to registered URLs.

## Events

| Event | Trigger |
|---|---|
| `scan.completed` | Scan finishes successfully |
| `scan.failed` | Scan fails |

## Payload

```json
{
  "event": "scan.completed",
  "scan_id": "2cb9f84c-a0ad-48a0-b523-d5b111cb2126",
  "project_id": "44444444-4444-4444-4444-444444444401",
  "scan_type": "sast",
  "status": "completed",
  "findings_count": 3,
  "timestamp": "2026-04-07T12:00:00Z"
}
```

## Signature verification

Payloads are signed with HMAC-SHA256 using the platform's `MSG_SIGNING_KEY`.
The signature is in the `X-SentinelCore-Signature` header:

```
X-SentinelCore-Signature: sha256=<hex-digest>
```

Verify in your receiver:
```python
import hmac, hashlib

def verify(body: bytes, signature: str, secret: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

## Delivery

- Timeout: 10 seconds per attempt
- Retries: 3 attempts with exponential backoff (2s, 4s, 6s)
- Non-2xx responses trigger retry

## Configuration

Webhooks are managed via the existing webhook CRUD API:
- `POST /api/v1/webhooks`
- `GET /api/v1/webhooks`
- `PUT /api/v1/webhooks/{id}`
- `DELETE /api/v1/webhooks/{id}`

Set `events` to include `"scan.completed"` to receive scan completion notifications.

## CI/CD Usage

### GitHub Actions (wait for scan, then fetch SARIF)

```yaml
- name: Wait for webhook or poll
  run: |
    # Option 1: Use a webhook receiver service
    # Option 2: Poll the scan status
    for i in $(seq 1 30); do
      STATUS=$(curl -s -H "Authorization: Bearer $SC_KEY" \
        $SC_URL/api/v1/scans/$SCAN_ID | jq -r '.scan.status')
      if [ "$STATUS" = "completed" ]; then break; fi
      sleep 10
    done

- name: Fetch SARIF
  run: |
    curl -H "Authorization: Bearer $SC_KEY" \
      $SC_URL/api/v1/scans/$SCAN_ID/report.sarif -o results.sarif
```
