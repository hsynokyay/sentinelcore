#!/usr/bin/env bash
# Fails if any call to policy.Evaluate remains in api handlers.
# Intentionally allowed: internal/policy/*.go (the shim itself), tests.
set -eu
matches=$(grep -rn "policy\.Evaluate" internal/controlplane/api/ || true)
if [ -n "$matches" ]; then
    echo "ERROR: policy.Evaluate still called outside middleware:" >&2
    echo "$matches" >&2
    exit 1
fi
echo "OK: no inline policy.Evaluate calls in handlers."
