# CCF API Helm Chart

This Helm chart deploys the Compliance Configuration Framework (CCF) API on Kubernetes following security best practices.

## What is Helm?

Helm is a package manager for Kubernetes that allows you to:
- Package your application as a "chart"
- Configure deployments using values files
- Manage releases and rollbacks
- Share and reuse configurations

## Prerequisites

- Kubernetes 1.25+
- Helm 3.8+
- PV provisioner support in the underlying infrastructure (for production)
- Metrics Server (for HPA)
- NGINX Ingress Controller (optional)
- cert-manager (optional, for TLS)

## Installing Helm

```bash
# macOS
brew install helm

# Linux
curl https://get.helm.sh/helm-v3.13.0-linux-amd64.tar.gz | tar xz
sudo mv linux-amd64/helm /usr/local/bin/

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

### Production Install with Security Best Practices

```bash
# 1. Create namespace
kubectl create namespace ccf-prod

# 2. Create secure password
export DB_PASSWORD=$(openssl rand -base64 32)

# 3. Install with secure configuration
helm install ccf-api ./ccf-api \
  -f ./ccf-api/values-prod.yaml \
  --namespace ccf-prod \
  --set postgresql.auth.password=$DB_PASSWORD \
  --set api.auth.jwtSecret=$(openssl rand -base64 32) \
  --set api.auth.apiKey=$(openssl rand -base64 32)
```

## Security Features

This Helm chart implements the following security best practices:

### 1. Secrets Management
- Database credentials stored in Kubernetes Secrets
- JWT secrets auto-generated if not provided
- Secrets referenced via environment variables
- Support for external secret operators

### 2. Network Security
- NetworkPolicy support for pod-to-pod communication
- TLS/SSL support for database connections
- Ingress with TLS termination
- Rate limiting support

### 3. Pod Security
- Non-root user execution
- Read-only root filesystem
- Security context with minimal privileges
- Capability dropping (ALL)
- Seccomp profiles

### 4. High Availability
- Pod Disruption Budgets
- Horizontal Pod Autoscaling
- Health checks (liveness & readiness)
- Rolling updates with zero downtime

## Configuration

### Key Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `api.replicaCount` | Number of API replicas | `1` |
| `api.image.repository` | API image repository | `api` |
| `api.image.tag` | API image tag | `local` |
| `api.auth.jwtSecret` | JWT secret (auto-generated if empty) | `""` |
| `api.resources.limits.memory` | Memory limit | `512Mi` |
| `api.resources.limits.cpu` | CPU limit | `500m` |
| `postgresql.enabled` | Enable PostgreSQL | `true` |
| `postgresql.auth.password` | Database password | `postgres` |
| `postgresql.ssl.enabled` | Enable SSL for database | `false` |
| `postgresql.persistence.enabled` | Enable persistent storage | `false` |
| `networkPolicy.enabled` | Enable network policies | `false` |
| `autoscaling.enabled` | Enable HPA | `false` |
| `podDisruptionBudget.enabled` | Enable PDB | `false` |

### Environment-Specific Values

```bash
# Development
helm install ccf-api ./ccf-api -f values-dev.yaml

# Staging
helm install ccf-api ./ccf-api -f values-staging.yaml

# Production
helm install ccf-api ./ccf-api -f values-prod.yaml
```

## Common Operations

### Upgrade Release

```bash
helm upgrade ccf-api ./ccf-api -f values-prod.yaml
```

### Check Status

```bash
helm status ccf-api
kubectl get pods -l app.kubernetes.io/name=ccf-api
```

### View Logs

```bash
kubectl logs -l app.kubernetes.io/name=ccf-api,app.kubernetes.io/component=api
```

### Access the API

```bash
# Port forward for local access
kubectl port-forward svc/ccf-api-api 8080:8080

# Via Ingress (if enabled)
curl https://api.ccf.yourdomain.com/health
```

### Database Operations

```bash
# Run migrations
kubectl exec deployment/ccf-api-api -- /api migrate up

# Create user
kubectl exec deployment/ccf-api-api -- /api users add \
  --email="admin@example.com" \
  --first-name="Admin" \
  --last-name="User"
```

## GitOps with ArgoCD

### Deploy with ArgoCD

1. Update `argocd/ccf-application.yaml`:
```yaml
spec:
  source:
    helm:
      parameters:
        - name: postgresql.auth.password
          value: <path:secret/data/ccf#password>  # Using ArgoCD Vault plugin
```

2. Apply the application:
```bash
kubectl apply -f argocd/ccf-application.yaml
```

## Troubleshooting

### Pod Not Starting

```bash
# Check pod status
kubectl describe pod -l app.kubernetes.io/name=ccf-api

# Check logs
kubectl logs -l app.kubernetes.io/name=ccf-api --previous
```

### Database Connection Issues

```bash
# Test database connection
kubectl exec deployment/ccf-api-api -- nc -zv ccf-api-postgresql 5432

# Check secrets
kubectl get secrets
kubectl describe secret ccf-api-secrets
```

### Performance Issues

```bash
# Check HPA status
kubectl get hpa

# Check resource usage
kubectl top pods -l app.kubernetes.io/name=ccf-api
```

## Production Checklist

- [ ] Use specific image tags (not `latest`)
- [ ] Set resource requests and limits
- [ ] Enable persistence for PostgreSQL
- [ ] Configure backups for database
- [ ] Use strong passwords (minimum 32 characters)
- [ ] Enable NetworkPolicies
- [ ] Configure Ingress with TLS
- [ ] Enable PodDisruptionBudget
- [ ] Enable HorizontalPodAutoscaler
- [ ] Configure monitoring and alerting
- [ ] Set up log aggregation
- [ ] Implement backup and disaster recovery
- [ ] Use external secret management (Vault, Sealed Secrets, etc.)

## Best Practices

1. **Never commit passwords to Git** - Use Helm's `--set` flag or external secret management
2. **Use separate values files** per environment
3. **Enable all security features** in production
4. **Regular updates** - Keep images and dependencies updated
5. **Monitor resource usage** and adjust limits accordingly
6. **Test upgrades** in staging before production
7. **Backup before major changes**

## Support

For issues and questions:
- GitHub Issues: https://github.com/compliance-framework/api/issues
- Documentation: https://docs.ccf.io