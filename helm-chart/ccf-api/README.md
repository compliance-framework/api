# CCF Helm Chart

This Helm chart deploys the Compliance Configuration Framework (CCF) on Kubernetes.

## What is Helm?

Helm is a package manager for Kubernetes. It allows you to:
- Package your application as a "chart"
- Configure deployments using values files
- Manage releases and rollbacks
- Share and reuse configurations

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- PV provisioner support in the underlying infrastructure (for production)

## Installing Helm

```bash
# macOS
brew install helm

# Or download from https://helm.sh/docs/intro/install/
```

## Installing the Chart

### Quick Install (Development)

```bash
# From the helm-chart directory
helm install my-ccf-api ./ccf-api

# Or with custom values
helm install my-ccf-api ./ccf-api -f ./ccf-api/values-dev.yaml
```

### Production Install

```bash
# First, customize values-prod.yaml with your settings
# Then install with production values
helm install ccf-api-prod ./ccf-api -f ./ccf-api/values-prod.yaml --namespace ccf-api --create-namespace
```

## Configuration

The following table lists the configurable parameters and their default values:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `api.replicaCount` | Number of API replicas | `1` |
| `api.image.repository` | API image repository | `api` |
| `api.image.tag` | API image tag | `local` |
| `api.service.type` | Kubernetes service type | `NodePort` |
| `api.service.port` | Service port | `8080` |
| `postgresql.enabled` | Enable PostgreSQL | `true` |
| `postgresql.auth.password` | PostgreSQL password | `postgres` |
| `postgresql.persistence.enabled` | Enable persistence | `false` |
| `ingress.enabled` | Enable ingress | `false` |

See `values.yaml` for full configuration options.

## Common Operations

### Install with custom name
```bash
helm install my-release ./ccf-api
```

### Upgrade a release
```bash
# After making changes to values
helm upgrade my-release ./ccf-api
```

### Install in specific namespace
```bash
helm install my-release ./ccf-api --namespace ccf-api --create-namespace
```

### Use environment-specific values
```bash
# Development
helm install dev-release ./ccf-api -f ./ccf-api/values-dev.yaml

# Production
helm install prod-release ./ccf-api -f ./ccf-api/values-prod.yaml
```

### Check deployment status
```bash
helm status my-release
kubectl get pods
```

### Uninstall
```bash
helm uninstall my-release
```

## Customizing Values

### Method 1: Using -f flag
```bash
helm install my-release ./ccf-api -f custom-values.yaml
```

### Method 2: Using --set flag
```bash
helm install my-release ./ccf-api \
  --set api.replicaCount=3 \
  --set postgresql.auth.password=mysecretpassword
```

### Method 3: Combination
```bash
helm install my-release ./ccf-api \
  -f values-prod.yaml \
  --set api.image.tag=v2.0.0
```

## Environment-Specific Deployments

### Development (Minikube)
```yaml
# values-dev.yaml
api:
  image:
    pullPolicy: Never
postgresql:
  persistence:
    enabled: false
```

### Production
```yaml
# values-prod.yaml
api:
  replicaCount: 3
  resources:
    limits:
      memory: 1Gi
postgresql:
  persistence:
    enabled: true
    size: 50Gi
ingress:
  enabled: true
  hosts:
    - host: ccf-api.example.com
```

## Helm Commands Reference

```bash
# List releases
helm list

# Get release values
helm get values my-release

# Get release manifest
helm get manifest my-release

# Rollback to previous version
helm rollback my-release

# Dry run (see what would be installed)
helm install my-release ./ccf-api --dry-run

# Debug installation
helm install my-release ./ccf-api --debug

# Package chart
helm package ./ccf-api
```

## Troubleshooting

### Check pod logs
```bash
kubectl logs deployment/my-release-ccf-api-api
```

### Describe pods
```bash
kubectl describe pod -l app.kubernetes.io/instance=my-release
```

### Get events
```bash
kubectl get events --sort-by='.lastTimestamp'
```

### Validate chart
```bash
helm lint ./ccf-api
```

## Advanced Features

### Using Helm Hooks
Helm supports hooks for lifecycle events (pre-install, post-upgrade, etc.)

### Using Subcharts
You can add dependencies like external PostgreSQL charts in `Chart.yaml`

### Template Debugging
```bash
# See rendered templates without installing
helm template my-release ./ccf-api
```

## Next Steps

1. Customize `values.yaml` for your environment
2. Set up CI/CD with Helm
3. Use Helm secrets for sensitive data
4. Consider using Helmfile for managing multiple environments
5. Look into ArgoCD for GitOps with Helm