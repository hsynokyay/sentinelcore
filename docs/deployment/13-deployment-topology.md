# 13. Deployment Topology

## 13.1 Deployment Models

SentinelCore supports three deployment models, each with specific infrastructure requirements and operational characteristics.

### 13.1.1 Model Comparison

| Aspect | Production (HA) | Small Team | Evaluation |
|---|---|---|---|
| Infrastructure | Kubernetes cluster (3+ nodes) | Kubernetes / k3s (1-3 nodes) | Docker Compose (single host) |
| HA | Full HA with replicas | Limited HA | No HA |
| Worker scaling | HPA (1–100 workers) | Manual (1–5 workers) | Fixed (1 worker each) |
| Database | PostgreSQL HA (Patroni) | PostgreSQL single | PostgreSQL container |
| Object storage | MinIO distributed (4+ nodes) | MinIO single | MinIO container |
| Vault | HA cluster (3 nodes) | Single node | Dev mode (unsealed) |
| Min resources | 24 vCPU, 64 GB RAM, 500 GB SSD | 8 vCPU, 16 GB RAM, 200 GB SSD | 4 vCPU, 8 GB RAM, 50 GB SSD |

## 13.2 Production Kubernetes Deployment

### 13.2.1 Namespace Layout

```
sentinelcore-system          # Control plane services
sentinelcore-scan-sast       # SAST workers
sentinelcore-scan-dast       # DAST workers (isolated network)
sentinelcore-data            # PostgreSQL, MinIO, NATS, Redis
sentinelcore-vault           # HashiCorp Vault
sentinelcore-monitoring      # Prometheus, Grafana, Loki, Tempo
sentinelcore-ingress         # API gateway, ingress controller
```

### 13.2.2 Node Topology

```
┌─────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                     │
│                                                          │
│  ┌─────────────────┐  ┌─────────────────┐               │
│  │  System Node 1  │  │  System Node 2  │               │
│  │  (control plane │  │  (control plane │               │
│  │   services,     │  │   services,     │               │
│  │   monitoring)   │  │   monitoring)   │               │
│  └─────────────────┘  └─────────────────┘               │
│                                                          │
│  ┌─────────────────┐  ┌─────────────────┐               │
│  │  Data Node 1    │  │  Data Node 2    │               │
│  │  (PostgreSQL,   │  │  (PostgreSQL    │               │
│  │   MinIO, NATS,  │  │   replica,      │               │
│  │   Redis, Vault) │  │   MinIO, NATS)  │               │
│  └─────────────────┘  └─────────────────┘               │
│                                                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────┐ │
│  │  Worker Node 1  │  │  Worker Node 2  │  │  ...    │ │
│  │  (SAST/DAST     │  │  (SAST/DAST     │  │  Worker │ │
│  │   workers)      │  │   workers)      │  │  Node N │ │
│  └─────────────────┘  └─────────────────┘  └─────────┘ │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 13.2.3 Node Affinity and Taints

```yaml
# System nodes: control plane services only
nodeSelector:
  sentinelcore.io/role: system

# Data nodes: stateful services only
nodeSelector:
  sentinelcore.io/role: data
tolerations:
  - key: sentinelcore.io/data
    operator: Exists

# Worker nodes: scan workers only
nodeSelector:
  sentinelcore.io/role: worker
tolerations:
  - key: sentinelcore.io/worker
    operator: Exists
```

### 13.2.4 Resource Specifications

| Service | CPU Request | CPU Limit | Memory Request | Memory Limit | Replicas |
|---|---|---|---|---|---|
| Control Plane | 500m | 2000m | 512Mi | 2Gi | 2 |
| Scan Orchestrator | 250m | 1000m | 256Mi | 1Gi | 2 (1 active) |
| SAST Worker | 1000m | 4000m | 2Gi | 8Gi | 1–20 (HPA) |
| DAST Worker | 500m | 2000m | 1Gi | 4Gi | 1–20 (HPA) |
| Auth Session Broker | 250m | 500m | 256Mi | 512Mi | 2 |
| CI/CD Connector | 250m | 500m | 256Mi | 512Mi | 2 |
| Vuln Intel Service | 500m | 1000m | 512Mi | 2Gi | 2 |
| Rule Repository | 250m | 500m | 256Mi | 1Gi | 2 |
| Correlation Engine | 500m | 2000m | 512Mi | 4Gi | 2 |
| Policy Engine | 250m | 500m | 256Mi | 512Mi | 2 |
| Audit Log Service | 250m | 500m | 256Mi | 512Mi | 2 |
| Reporting Service | 500m | 2000m | 512Mi | 4Gi | 2 |
| Update Manager | 250m | 500m | 256Mi | 512Mi | 1 |
| PostgreSQL | 2000m | 4000m | 4Gi | 16Gi | 2 (primary + replica) |
| MinIO | 1000m | 2000m | 2Gi | 8Gi | 4 (distributed) |
| NATS | 500m | 1000m | 512Mi | 2Gi | 3 (cluster) |
| Redis | 250m | 500m | 512Mi | 2Gi | 2 (sentinel) |
| Vault | 250m | 500m | 256Mi | 1Gi | 3 (HA) |

### 13.2.5 Horizontal Pod Autoscaling

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: sast-worker-hpa
  namespace: sentinelcore-scan-sast
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: sentinelcore-sast-worker
  minReplicas: 1
  maxReplicas: 20
  metrics:
    - type: External
      external:
        metric:
          name: nats_consumer_pending_count
          selector:
            matchLabels:
              consumer: sast-dispatch
        target:
          type: AverageValue
          averageValue: "5"    # Scale up when 5+ pending messages per worker
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
        - type: Pods
          value: 4
          periodSeconds: 60
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Pods
          value: 2
          periodSeconds: 120
```

## 13.3 Helm Chart Structure

```
sentinelcore/
├── Chart.yaml
├── values.yaml                    # Default values
├── values-production.yaml         # Production overrides
├── values-small.yaml              # Small team overrides
├── values-airgapped.yaml          # Air-gapped overrides
├── templates/
│   ├── _helpers.tpl
│   ├── namespaces.yaml
│   ├── network-policies/
│   │   ├── default-deny.yaml
│   │   ├── control-plane.yaml
│   │   ├── scan-workers.yaml
│   │   └── data-tier.yaml
│   ├── control-plane/
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   ├── serviceaccount.yaml
│   │   ├── configmap.yaml
│   │   └── hpa.yaml
│   ├── orchestrator/
│   │   └── ...
│   ├── sast-worker/
│   │   └── ...
│   ├── dast-worker/
│   │   └── ...
│   ├── ... (each service)
│   ├── ingress/
│   │   └── ingress.yaml
│   ├── monitoring/
│   │   ├── prometheus-rules.yaml
│   │   ├── grafana-dashboards.yaml
│   │   └── alertmanager-config.yaml
│   └── jobs/
│       ├── db-migrate.yaml        # Pre-upgrade hook
│       └── integrity-check.yaml   # CronJob
└── crds/                          # Custom Resource Definitions (if any)
```

## 13.4 Storage Requirements

### 13.4.1 Persistent Volume Claims

| Component | Storage Class | Size (Production) | Access Mode |
|---|---|---|---|
| PostgreSQL primary | SSD (high IOPS) | 200Gi | ReadWriteOnce |
| PostgreSQL replica | SSD | 200Gi | ReadWriteOnce |
| MinIO (per node) | SSD or HDD | 500Gi | ReadWriteOnce |
| NATS JetStream | SSD | 50Gi | ReadWriteOnce |
| Redis AOF | SSD | 10Gi | ReadWriteOnce |
| Vault data | SSD | 10Gi | ReadWriteOnce |
| Prometheus | SSD or HDD | 100Gi | ReadWriteOnce |
| Loki | HDD | 200Gi | ReadWriteOnce |

### 13.4.2 Ephemeral Storage

| Component | Usage | Type | Size Limit |
|---|---|---|---|
| SAST Worker | Source code checkout, analysis workspace | tmpfs / emptyDir | 10Gi per scan |
| DAST Worker | HTTP trace buffering, screenshots | emptyDir | 5Gi per scan |
| Report Generator | Temporary report rendering | emptyDir | 2Gi |

## 13.5 Ingress Configuration

### 13.5.1 API Gateway

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: sentinelcore-api
  namespace: sentinelcore-ingress
  annotations:
    # TLS
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    # Rate limiting
    nginx.ingress.kubernetes.io/limit-rps: "100"
    nginx.ingress.kubernetes.io/limit-connections: "50"
    # Request size (for bundle uploads)
    nginx.ingress.kubernetes.io/proxy-body-size: "500m"
    # Timeouts
    nginx.ingress.kubernetes.io/proxy-read-timeout: "300"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - sentinelcore.internal.example.com
      secretName: sentinelcore-tls
  rules:
    - host: sentinelcore.internal.example.com
      http:
        paths:
          - path: /api/
            pathType: Prefix
            backend:
              service:
                name: sentinelcore-controlplane
                port:
                  number: 8080
          - path: /webhook/
            pathType: Prefix
            backend:
              service:
                name: sentinelcore-cicd-connector
                port:
                  number: 8081
```

## 13.6 DNS and Service Discovery

| DNS Record | Target | Purpose |
|---|---|---|
| sentinelcore.internal.example.com | Ingress LB | Primary API endpoint |
| sentinelcore-grafana.internal.example.com | Grafana Service | Monitoring dashboards |
| sentinelcore-vault.internal.example.com | Vault Service | Vault UI (admin only) |

Internal service discovery uses Kubernetes DNS:
- `sentinelcore-controlplane.sentinelcore-system.svc.cluster.local`
- `sentinelcore-nats.sentinelcore-data.svc.cluster.local`
- etc.
