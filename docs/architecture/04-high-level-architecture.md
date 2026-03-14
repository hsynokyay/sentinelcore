# 4. High-Level Architecture

## 4.1 Architecture Overview

SentinelCore follows a **microservices architecture** deployed on Kubernetes, organized into four logical tiers:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        EXTERNAL INTEGRATION TIER                        │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │  CI/CD       │  │  SCM         │  │  Identity   │  │  Vuln Feed  │ │
│  │  Pipelines   │  │  Repositories│  │  Providers  │  │  Sources    │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘  └──────┬──────┘ │
└─────────┼──────────────────┼─────────────────┼────────────────┼────────┘
          │                  │                 │                │
┌─────────┼──────────────────┼─────────────────┼────────────────┼────────┐
│         ▼                  ▼                 ▼                ▼        │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    API GATEWAY / INGRESS                        │   │
│  │          (TLS termination, rate limiting, AuthN/AuthZ)          │   │
│  └─────────────────────────┬───────────────────────────────────────┘   │
│                            │                                           │
│  ┌─────────────────────────┼──────────────────────────────────────┐   │
│  │                  CONTROL PLANE TIER                             │   │
│  │                         │                                      │   │
│  │  ┌─────────────┐  ┌────┴────────┐  ┌─────────────┐            │   │
│  │  │  Control     │  │  Scan       │  │  Policy     │            │   │
│  │  │  Plane API   │  │  Orchestr.  │  │  Engine     │            │   │
│  │  └──────┬───────┘  └─────┬───────┘  └──────┬──────┘            │   │
│  │         │                │                  │                   │   │
│  │  ┌──────┴───────┐  ┌────┴────────┐  ┌──────┴──────┐           │   │
│  │  │  Auth Session│  │  CI/CD      │  │  Reporting  │           │   │
│  │  │  Broker      │  │  Connector  │  │  Service    │           │   │
│  │  └──────────────┘  └─────────────┘  └─────────────┘           │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                  DATA PROCESSING TIER                           │   │
│  │                                                                │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │   │
│  │  │  Correlation │  │  Vuln Intel │  │  Rule       │            │   │
│  │  │  Engine      │  │  Service    │  │  Repository │            │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘            │   │
│  │                                                                │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │   │
│  │  │  Update      │  │  Audit Log  │  │  AI Assist  │            │   │
│  │  │  Manager     │  │  Service    │  │  (optional) │            │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘            │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                  SCAN EXECUTION TIER                            │   │
│  │                                                                │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │   │
│  │  │  SAST       │  │  SAST       │  │  SAST       │            │   │
│  │  │  Worker 1   │  │  Worker 2   │  │  Worker N   │            │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘            │   │
│  │                                                                │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │   │
│  │  │  DAST       │  │  DAST       │  │  DAST       │            │   │
│  │  │  Worker 1   │  │  Worker 2   │  │  Worker N   │            │   │
│  │  │  (isolated) │  │  (isolated) │  │  (isolated) │            │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘            │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                  DATA PERSISTENCE TIER                          │   │
│  │                                                                │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │   │
│  │  │PostgreSQL│  │  MinIO   │  │  NATS    │  │  Redis   │      │   │
│  │  │(findings,│  │(evidence,│  │JetStream │  │(cache,   │      │   │
│  │  │ config,  │  │artifacts,│  │(message  │  │ sessions)│      │   │
│  │  │ audit)   │  │ reports) │  │ queue)   │  │          │      │   │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘      │   │
│  │                                                                │   │
│  │  ┌──────────────────────────┐                                  │   │
│  │  │  HashiCorp Vault         │                                  │   │
│  │  │  (secrets, credentials,  │                                  │   │
│  │  │   encryption keys)       │                                  │   │
│  │  └──────────────────────────┘                                  │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                        SENTINELCORE BOUNDARY                          │
└───────────────────────────────────────────────────────────────────────┘
```

## 4.2 Tier Responsibilities

### 4.2.1 External Integration Tier
- **Boundary:** Outside SentinelCore's trust boundary
- **Purpose:** Inbound triggers (CI/CD webhooks, SCM events) and outbound data pulls (vuln feeds, identity verification)
- **Security:** All inbound traffic passes through the API Gateway with TLS, rate limiting, and authentication. Outbound connections are allowlisted by destination.

### 4.2.2 Control Plane Tier
- **Boundary:** Trusted internal services
- **Purpose:** API serving, scan lifecycle management, policy enforcement, credential brokering, CI/CD integration, report generation
- **Security:** mTLS between all services. OPA policy checks on every request. All state changes produce audit events.
- **Scaling:** Stateless services scale horizontally behind a load balancer. Orchestrator uses leader election for singleton work.

### 4.2.3 Data Processing Tier
- **Boundary:** Trusted internal services with elevated data access
- **Purpose:** Finding correlation, vulnerability intelligence management, rule storage, update application, audit log management
- **Security:** Read/write access scoped per service. Correlation Engine has read-only access to findings. Audit Log Service has append-only access to audit tables.

### 4.2.4 Scan Execution Tier
- **Boundary:** Semi-trusted — workers handle untrusted code and interact with external targets
- **Purpose:** Execute SAST and DAST scan workloads
- **Security:** Workers run in isolated pods with restricted network policies. DAST workers run in dedicated network namespaces with egress limited to approved scan targets. Workers authenticate to the control plane via short-lived mTLS certificates. Workers cannot access the database directly — all data flows through the message queue.

### 4.2.5 Data Persistence Tier
- **Boundary:** Trusted, restricted access
- **Purpose:** Durable storage for all platform data
- **Security:** Network policies restrict access to specific services. Encryption at rest enabled. Database connections require mTLS. Vault requires explicit unsealing.

## 4.3 Communication Patterns

### 4.3.1 Synchronous (Request-Response)
- **Protocol:** gRPC with mTLS
- **Used for:** Control plane API calls, policy evaluation, credential retrieval
- **Timeout:** Configurable per-endpoint, default 30 seconds
- **Retry:** Exponential backoff with jitter, max 3 retries

### 4.3.2 Asynchronous (Event-Driven)
- **Protocol:** NATS JetStream
- **Used for:** Scan dispatch, result submission, audit event publishing, vuln feed processing
- **Delivery:** At-least-once with idempotent consumers
- **Retention:** Stream retention configurable per topic (default: 7 days)

### 4.3.3 Message Flow Summary

```
CI/CD Trigger ──► API Gateway ──► Control Plane ──► Scan Orchestrator
                                                         │
                                                         ▼
                                                   NATS JetStream
                                                    ┌────┴────┐
                                                    ▼         ▼
                                              SAST Worker  DAST Worker
                                                    │         │
                                                    ▼         ▼
                                               NATS JetStream
                                                    │
                                                    ▼
                                            Correlation Engine
                                                    │
                                              ┌─────┴──────┐
                                              ▼            ▼
                                        Findings DB   Evidence Store
```

## 4.4 Network Architecture

### 4.4.1 Network Segments

| Segment | CIDR (example) | Purpose | Egress |
|---|---|---|---|
| control-plane | 10.0.1.0/24 | Control plane services | Internal only + vuln feeds (online mode) |
| scan-workers | 10.0.2.0/24 | SAST workers | Internal only (no external egress) |
| dast-workers | 10.0.3.0/24 | DAST workers | Approved scan targets only (dynamic NetworkPolicy) |
| data | 10.0.4.0/24 | Databases, object store, cache | Internal only |
| ingress | 10.0.0.0/24 | API gateway, load balancer | External (inbound only) |

### 4.4.2 Network Policies

- **Default deny** on all namespaces
- Explicit allow rules per service-to-service communication path
- DAST workers receive **dynamic NetworkPolicy** resources generated per-scan, allowing egress only to the approved scan targets
- Scan target NetworkPolicies are created by the Orchestrator (which validates scope) and destroyed on scan completion

## 4.5 Service Discovery and Mesh

- **Service Discovery:** Kubernetes native DNS (CoreDNS)
- **Load Balancing:** Kubernetes Services with endpoint slices
- **Service Mesh (optional):** Istio or Linkerd for advanced traffic management and observability. Not required — mTLS is handled at the application layer by default.
- **Circuit Breaking:** Implemented in gRPC interceptors. Configurable per-service.

## 4.6 Configuration Management

All configuration follows a layered model:

```
Priority (highest to lowest):
1. Environment variables (for secrets references only)
2. ConfigMap overrides (per-deployment)
3. Helm values.yaml (per-environment)
4. Built-in defaults (compiled into binaries)
```

Configuration is validated at startup against a JSON Schema. Invalid configuration prevents service startup with explicit error messages.
