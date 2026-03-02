# Hetzner Firewall Operator

A Kubernetes operator that automatically manages [Hetzner Cloud Firewall](https://docs.hetzner.com/cloud/firewalls) rules based on the current nodes in your cluster. Designed for **RKE2 + Cilium** clusters running on Hetzner Cloud.

When nodes join or leave the cluster, the operator updates the Hetzner Cloud Firewall to allow only the required ports between the current set of node IPs. It supports both IPv4 and IPv6.

Optionally, the Helm chart can also deploy **Cilium Host Firewall** policies (`CiliumClusterwideNetworkPolicy`) that enforce the same rules at the kernel level using eBPF, providing defense in depth.

## How It Works

1. The operator watches Kubernetes `Node` resources using controller-runtime.
2. It extracts each node's Hetzner Cloud server ID from `spec.providerID` (`hcloud://SERVER_ID`).
3. It reads each node's IPv4 and IPv6 addresses from `status.addresses`.
4. It classifies nodes as control-plane or worker based on standard labels (`node-role.kubernetes.io/control-plane`, `node-role.kubernetes.io/master`, `node-role.kubernetes.io/etcd`).
5. It computes the desired firewall rules and applies them via the Hetzner Cloud API.
6. It attaches the firewall to any new servers that don't have it yet.

Reconciliation is triggered by node events (create, delete, address change) and runs periodically as a safety net.

## Port Rules

The following ports are managed for an RKE2 + Cilium cluster:

| Port | Protocol | Source | Description |
|------|----------|--------|-------------|
| 9345 | TCP | Cluster nodes | RKE2 supervisor API (node registration) |
| 6443 | TCP | Cluster nodes | Kubernetes API server |
| 8472 | UDP | Cluster nodes | Cilium VXLAN overlay |
| 10250 | TCP | Cluster nodes | kubelet API |
| 4240 | TCP | Cluster nodes | Cilium health checks |
| 4245 | TCP | Cluster nodes | Hubble Relay |
| ICMP | - | Cluster nodes | Ping, Path MTU Discovery |
| 2379 | TCP | Control-plane nodes | etcd client requests |
| 2380 | TCP | Control-plane nodes | etcd peer communication |
| 80 | TCP | Public | HTTP ingress |
| 443 | TCP | Public | HTTPS ingress |
| 30000-32767 | TCP+UDP | Configurable | NodePort services |
| 22 | TCP | Configurable | SSH access |

## Prerequisites

- A Kubernetes cluster running on Hetzner Cloud (nodes must have `hcloud://` provider IDs)
- A Hetzner Cloud API token with read/write permissions
- Helm 3
- Cilium CNI (required if using the Cilium Host Firewall policies)

## Deployment

### Quick Start

```bash
helm install hetzner-fw ./charts/hetzner-firewall-operator \
  -n hetzner-firewall-operator --create-namespace \
  --set hcloudToken=YOUR_HCLOUD_TOKEN \
  --set operator.firewallName=my-cluster \
  --set 'operator.allowSSHFrom={YOUR_IP/32}'
```

### Using an Existing Secret

If you manage secrets externally (e.g. via Sealed Secrets or External Secrets), create a secret with a `HCLOUD_TOKEN` key and reference it:

```bash
kubectl create secret generic hcloud-credentials \
  -n hetzner-firewall-operator \
  --from-literal=HCLOUD_TOKEN=YOUR_TOKEN

helm install hetzner-fw ./charts/hetzner-firewall-operator \
  -n hetzner-firewall-operator --create-namespace \
  --set existingSecret=hcloud-credentials
```

### With Cilium Host Firewall Policies

To deploy both Hetzner Cloud Firewall management and Cilium Host Firewall policies:

```bash
helm install hetzner-fw ./charts/hetzner-firewall-operator \
  -n hetzner-firewall-operator --create-namespace \
  --set hcloudToken=YOUR_HCLOUD_TOKEN \
  --set 'operator.allowSSHFrom={YOUR_IP/32}' \
  --set ciliumPolicies.enabled=true \
  --set ciliumPolicies.defaultDeny=true
```

> **Warning:** Enabling `ciliumPolicies.defaultDeny` will block all host ingress traffic not explicitly allowed by the other policies. Make sure your SSH CIDR and all required ports are configured before enabling this, or you will lose access to your nodes.

### Building the Container Image

```bash
docker build -t ghcr.io/atroo/hetzner-firewall-operator:latest .
docker push ghcr.io/atroo/hetzner-firewall-operator:latest
```

### Running Locally (Development)

```bash
export HCLOUD_TOKEN=your-token
go run ./cmd/operator \
  --firewall-name=k8s-cluster \
  --allow-ssh-from=YOUR_IP/32 \
  --reconcile-interval=1m
```

This uses your local `~/.kube/config` to connect to the cluster.

## Helm Values Reference

### Image

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `image.repository` | string | `ghcr.io/atroo/hetzner-firewall-operator` | Container image repository |
| `image.tag` | string | `latest` | Container image tag |
| `image.pullPolicy` | string | `IfNotPresent` | Image pull policy |
| `imagePullSecrets` | list | `[]` | Image pull secrets for private registries |

### Authentication

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `hcloudToken` | string | `""` | Hetzner Cloud API token. Creates a Secret automatically. |
| `existingSecret` | string | `""` | Name of an existing Secret with a `HCLOUD_TOKEN` key. If set, `hcloudToken` is ignored. |

### Operator Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `operator.firewallName` | string | `k8s-cluster` | Name of the Hetzner Cloud Firewall to create and manage |
| `operator.reconcileInterval` | string | `5m` | Interval between full reconciliation runs (Go duration) |
| `operator.nodePortPublic` | bool | `false` | If `true`, NodePort range (30000-32767) is open to `0.0.0.0/0`. If `false`, only cluster node IPs are allowed. |
| `operator.allowSSHFrom` | list | `[]` | CIDRs allowed SSH access. Empty = no SSH rule. Example: `["1.2.3.4/32", "10.0.0.0/8"]` |
| `operator.labelSelector` | string | `""` | Kubernetes label selector to filter which nodes the operator considers |
| `operator.metricsAddr` | string | `:8080` | Bind address for the Prometheus metrics endpoint |
| `operator.healthAddr` | string | `:8081` | Bind address for health/readiness probes |

### Deployment

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `replicaCount` | int | `2` | Number of replicas. >1 enables HA via leader election. |
| `resources.requests.cpu` | string | `10m` | CPU request |
| `resources.requests.memory` | string | `32Mi` | Memory request |
| `resources.limits.cpu` | string | `100m` | CPU limit |
| `resources.limits.memory` | string | `64Mi` | Memory limit |
| `nodeSelector` | object | `{}` | Node selector for the operator pod |
| `tolerations` | list | `[]` | Tolerations for the operator pod |
| `affinity` | object | `{}` | Affinity rules for the operator pod |
| `podAnnotations` | object | `{}` | Additional pod annotations |
| `podLabels` | object | `{}` | Additional pod labels |

### RBAC & Service Account

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `serviceAccount.create` | bool | `true` | Create a ServiceAccount |
| `serviceAccount.name` | string | `""` | Override ServiceAccount name (defaults to release fullname) |
| `serviceAccount.annotations` | object | `{}` | ServiceAccount annotations |
| `rbac.create` | bool | `true` | Create ClusterRole and ClusterRoleBinding |

### Monitoring

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `serviceMonitor.enabled` | bool | `false` | Create a Prometheus `ServiceMonitor` resource |
| `serviceMonitor.interval` | string | `60s` | Scrape interval |
| `serviceMonitor.labels` | object | `{}` | Additional labels on the ServiceMonitor (e.g. for Prometheus selector matching) |

### Cilium Host Firewall Policies

These settings control the optional `CiliumClusterwideNetworkPolicy` resources that enforce the same port rules at the eBPF/kernel level.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ciliumPolicies.enabled` | bool | `false` | Deploy Cilium Host Firewall policies |
| `ciliumPolicies.defaultDeny` | bool | `false` | Deploy a default-deny host ingress policy. **Warning:** will block all traffic not explicitly allowed. |
| `ciliumPolicies.apiServerPublic` | bool | `false` | Allow external access to the Kubernetes API server (port 6443) |
| `ciliumPolicies.allNodesSelector` | object | `{}` | Override `nodeSelector` for all-node policies. Defaults to `kubernetes.io/os: linux`. |
| `ciliumPolicies.controlPlaneSelector` | object | `{}` | Override `nodeSelector` for the etcd policy. Defaults to `node-role.kubernetes.io/control-plane: "true"`. |

## Architecture

```
                    +-----------------------+
                    |   Hetzner Cloud API   |
                    |   (Firewall Rules)    |
                    +-----------^-----------+
                                |
                    +-----------+-----------+
                    | hetzner-firewall-     |
                    | operator              |
                    | (controller-runtime)  |
                    +-----------^-----------+
                                |
                    watches Node resources
                                |
          +----------+----------+----------+
          |          |          |          |
       +--+--+   +--+--+   +--+--+   +--+--+
       |Node1|   |Node2|   |Node3|   |Node4|
       |CP   |   |CP   |   |Wkr  |   |Wkr  |
       +-----+   +-----+   +-----+   +-----+

  Hetzner Firewall (edge):  IP-based rules per node
  Cilium Host FW (kernel):  eBPF policies on each node
```

The two firewall layers are complementary:

- **Hetzner Cloud Firewall** filters traffic at the network edge before it reaches the server. It uses IP/CIDR + port rules and is managed dynamically by the operator.
- **Cilium Host Firewall** filters traffic at the kernel level using eBPF on each node. It uses Kubernetes-native identity (`remote-node`, `world`, `host`) and is deployed as static policies via the Helm chart.

## License

MIT
