# Release Security — trust model

For customer deployment teams and security review.

SentinelCore releases ship three guarantees, attached to every image
at release time by the GitHub Actions `release.yml` workflow:

1. **Provenance** — the image was built from this exact repository
   at the tagged commit, by our CI (verifiable via `cosign` against
   the GitHub OIDC issuer).
2. **Integrity** — the image's content digest is pinned to the
   signature; any alteration invalidates the signature.
3. **Transparency** — the signing record lives in the public
   [Rekor](https://rekor.sigstore.dev) transparency log. Any
   signature we produce is publicly auditable.

## How to verify

### With `cosign` directly

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/hsynokyay/sentinelcore/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/hsynokyay/sentinelcore/controlplane:v1.2.3
```

Success output includes `Signed by:` with the GitHub workflow URL,
proving the image came from our CI pipeline.

### With the bundled script

```bash
./scripts/verify-release.sh v1.2.3
```

Verifies every service in one pass and checks the SBOM is attached
and non-empty. Exit code is 0 on full success, 1 on any failure.

### Inspecting the SBOM

```bash
cosign download sbom ghcr.io/hsynokyay/sentinelcore/controlplane:v1.2.3 \
  | jq '.components[] | select(.name | contains("crypto"))'
```

The SBOM is CycloneDX JSON, one per service. Compliance teams can
scan it against their own allow/deny lists (license, CVE, etc.)
before admitting the image into a cluster.

## Enforcement at deploy time

### Kubernetes

Install the [sigstore policy-controller](https://docs.sigstore.dev/policy-controller/overview/)
admission webhook and create a `ClusterImagePolicy`:

```yaml
apiVersion: policy.sigstore.dev/v1alpha1
kind: ClusterImagePolicy
metadata:
  name: sentinelcore-signed
spec:
  images:
    - glob: "ghcr.io/hsynokyay/sentinelcore/*"
  authorities:
    - keyless:
        url: https://fulcio.sigstore.dev
        identities:
          - issuer: https://token.actions.githubusercontent.com
            subjectRegExp: '^https://github\.com/hsynokyay/sentinelcore/'
```

With that policy applied, any pod pulling an unsigned SentinelCore
image is rejected by the cluster.

### Docker Compose (self-hosted)

Docker Compose has no native admission control. Run
`verify-release.sh <tag>` on the host BEFORE `docker compose pull`
as part of your deploy script:

```bash
#!/usr/bin/env bash
set -e
TAG="$1"
./verify-release.sh "$TAG" || { echo "release verification failed"; exit 1; }
docker compose pull
docker compose up -d
```

## Rotation / key recovery

Because we use **keyless** signing (cosign + Fulcio + Rekor), there
is no long-lived signing key to leak or rotate. Every signature is
bound to a short-lived certificate issued by Fulcio against our
GitHub workflow's OIDC identity.

Compromise scenarios:

| Scenario | Impact | Recovery |
|---|---|---|
| GitHub org credential theft | Attacker could publish a signed image under our identity | Revoke GitHub org access, publish an advisory listing affected tags, retag clean versions |
| A specific release was tampered with pre-signing | That image's signature is valid but covers bad content | Burn the tag, publish a clean `vX.Y.Z-post1` tag, update advisory with the burned digest |
| Rekor transparency log compromised | All signatures after the compromise point untrustworthy | Sigstore incident response; coordinate with upstream, revalidate recent releases |

## Phase 8 references

- Plan: `docs/superpowers/plans/2026-04-19-phase8-platform-hardening.md` (§7.4)
- Workflow: `.github/workflows/release.yml`
- Verify script: `scripts/verify-release.sh`
