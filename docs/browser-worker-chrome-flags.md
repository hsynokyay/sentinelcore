# Browser Worker Chrome Flags Specification

**Status:** Reviewed Artifact
**Applies to:** `cmd/dast-browser-worker`
**Source:** Phase 5a Security Review

This document specifies every Chrome launch flag used by the browser DAST worker, its security purpose, and what issue from the security review it mitigates.

## Flags

| Flag | Value | Security Property | Mitigates |
|------|-------|------------------|-----------|
| `headless` | `new` | Eliminates GUI attack surface, uses modern headless mode | General |
| `no-sandbox` | `true` | Disables Chrome's internal sandbox. **Compensated by**: container user namespaces, seccomp-bpf from container runtime, iptables Layer 2, non-root user | C2 |
| `disable-gpu` | `true` | Eliminates GPU process attack surface | M8 |
| `disable-software-rasterizer` | `true` | No software rendering subprocess | M8 |
| `disable-dev-shm-usage` | `true` | Uses `/tmp` instead of `/dev/shm`, avoids shm size issues | H11 |
| `disable-background-networking` | `true` | Prevents speculative/background network activity | M1 |
| `disable-features` | `ServiceWorker,WebRTC,NetworkPrediction,AutofillServerCommunication` | ServiceWorker: prevents credential caching (H3). WebRTC: prevents internal IP leak via ICE candidates (H4). NetworkPrediction: no speculative DNS/TCP (M1). Autofill: no autofill network calls (L1) | H3, H4, M1 |
| `disable-blink-features` | `AutomationControlled` | Removes `navigator.webdriver` flag that triggers bot detection | M4 |
| `disable-component-update` | `true` | No background Chrome component downloads | General |
| `disable-default-apps` | `true` | Minimal Chrome installation, no default extensions | General |
| `dns-prefetch-disable` | `true` | Prevents speculative DNS resolution for page links | M1 |
| `no-first-run` | `true` | Skips first-run experience and associated network calls | General |
| `js-flags` | `--max-old-space-size=512` | Limits V8 heap to 512MB, prevents unbounded memory growth | H10 |
| `user-data-dir` | `/tmp/sentinel-chrome-<job-id>` | Per-job profile isolation. Directory is on tmpfs, destroyed after each scan. Prevents cross-job credential leakage | H1, H3 |

## Compensating Controls for --no-sandbox

Chrome's `--no-sandbox` disables the multi-process sandbox (seccomp-bpf + user namespaces + PID namespace inside Chrome). This is required because containers typically lack the `SYS_ADMIN` capability needed for Chrome to create its own user namespaces.

Compensating controls that provide equivalent or stronger isolation:

1. **Container seccomp profile** (`deploy/seccomp/dast-browser-worker.json`): Applied by the container runtime, covers all processes including Chrome
2. **Container namespaces**: PID, network, mount, UTS namespaces isolate the browser from the host
3. **iptables Layer 2** (`deploy/iptables/browser-worker.sh`): Kernel-level network filtering that Chrome's sandbox does not provide
4. **Non-root user**: Chrome runs as `sentinel` (UID 1000), limiting exploit impact
5. **Read-only rootfs**: No persistent filesystem modifications possible
6. **Memory limits**: Container-level 2GB limit + V8 512MB limit
7. **PID limit**: 256 processes maximum, prevents fork bombs

## Update Cadence

Chrome/Chromium version should be updated monthly or immediately when a Critical/High CVE is published affecting the headless shell. The base image `chromedp/headless-shell:stable` tracks Chrome stable channel.
