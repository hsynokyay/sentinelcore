#!/usr/bin/env bash
set -euo pipefail

# Phase 8 Wave 3 — customer-facing release-verification script.
#
# Proves that a released SentinelCore image:
#   1. Was built by our GitHub Actions workflow (cosign identity check)
#   2. Is signed in the public Rekor transparency log
#   3. Has an attached CycloneDX SBOM
#
# Usage:
#   verify-release.sh <tag>
#   verify-release.sh v1.2.3
#
# Services checked by default: controlplane, audit-service,
# sast-worker, dast-worker, notification-worker, retention-worker.
# Override via SC_SERVICES="svc1 svc2".
#
# Requires: cosign (>=2.x), jq.

TAG="${1:-}"
if [[ -z "${TAG}" ]]; then
    cat >&2 <<EOF
usage: $0 <tag>
example: $0 v1.2.3
EOF
    exit 2
fi

REGISTRY_BASE="${SC_REGISTRY:-ghcr.io/hsynokyay/sentinelcore}"
SERVICES="${SC_SERVICES:-controlplane audit-service sast-worker dast-worker notification-worker retention-worker}"
OIDC_ISSUER="${SC_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
IDENTITY_REGEX="${SC_IDENTITY_REGEX:-^https://github\.com/hsynokyay/sentinelcore/}"

for bin in cosign jq; do
    command -v "$bin" >/dev/null || {
        echo "error: $bin not on PATH" >&2
        exit 2
    }
done

fail=0
pass=0

echo "=== SentinelCore ${TAG} release verification ==="
echo "registry:  ${REGISTRY_BASE}"
echo "identity:  ${IDENTITY_REGEX}"
echo "issuer:    ${OIDC_ISSUER}"
echo ""

for svc in ${SERVICES}; do
    ref="${REGISTRY_BASE}/${svc}:${TAG}"
    printf "  %s " "${ref}"

    # 1. Signature + identity check.
    if cosign verify \
            --certificate-identity-regexp "${IDENTITY_REGEX}" \
            --certificate-oidc-issuer "${OIDC_ISSUER}" \
            "${ref}" >/dev/null 2>&1; then
        printf "✓ signed"
    else
        printf "✗ signature FAILED"
        fail=$((fail + 1))
        echo ""
        continue
    fi

    # 2. SBOM presence.
    if cosign download sbom "${ref}" 2>/dev/null | jq -e . >/dev/null; then
        printf " · ✓ sbom"
    else
        printf " · ✗ sbom MISSING"
        fail=$((fail + 1))
        echo ""
        continue
    fi

    # 3. SBOM component count (smoke test — 0 components = bad SBOM).
    n=$(cosign download sbom "${ref}" 2>/dev/null \
        | jq '[.components[]?] | length')
    if [[ "${n}" -gt 0 ]]; then
        printf " (%d components)" "${n}"
        pass=$((pass + 1))
        echo ""
    else
        printf " · ✗ SBOM has 0 components"
        fail=$((fail + 1))
        echo ""
    fi
done

echo ""
echo "=== Result ==="
echo "  passed: ${pass}"
echo "  failed: ${fail}"

if [[ ${fail} -gt 0 ]]; then
    exit 1
fi
echo "All services verified. Proceed with deployment."
