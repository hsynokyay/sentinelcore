# SentinelCore Scanner Bypass — Go SDK

Reference middleware for verifying SentinelCore DAST scanner traffic in your
test/staging Go applications.

## Install

go get github.com/sentinelcore/customer-sdks/scanner-bypass-go

## Setup

1. Obtain your bypass HMAC secret from your SentinelCore administrator.
2. Store the secret in your secret manager (do NOT commit to source).
3. Wrap your HTTP handlers:

import scanner_bypass "github.com/sentinelcore/customer-sdks/scanner-bypass-go"

func main() {
    secret := loadSecretFromVault("sentinelcore_bypass")
    handler := scanner_bypass.Middleware(secret)(yourHandler)
    http.ListenAndServe(":8080", handler)
}

func yourLoginHandler(w http.ResponseWriter, r *http.Request) {
    if scanner_bypass.IsTrustedScanner(r) {
        // Skip CAPTCHA / rate limit
    } else {
        // Normal flow with CAPTCHA
    }
}

## Security

- Deploy ONLY in test/staging environments.
- The middleware verifies HMAC, time window (5 min), nonce uniqueness, and
  host binding.
- A failed verification falls through silently (request continues without
  trusted context); your existing protections still apply.
