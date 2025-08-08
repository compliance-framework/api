# Production Deployment Guide for CCF API

This guide explains how to deploy CCF API to production using ArgoCD with Sealed Secrets for secure password management.

## Prerequisites

- Kubernetes cluster (production-grade)
- ArgoCD installed and configured
- Sealed Secrets controller installed
- `kubeseal` CLI installed
- Access to container registry

## Architecture Overview

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│   ArgoCD    │────▶│ Sealed Secret│────▶│ Kubernetes      │
│ Application │     │  Controller  │     │ Secrets         │
└─────────────┘     └──────────────┘     └─────────────────┘
      │                                           │
      │                                           ▼
      │                                   ┌───────────────┐
      └──────────────────────────────────▶│  CCF API Pods │
                                          └───────────────┘
```

## Step-by-Step Deployment

### 1. Install Sealed Secrets Controller (One-time setup)

```bash
# Install controller
kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.24.5/controller.yaml

# Install CLI (macOS)
brew install kubeseal

# Verify installation
kubectl get pods -n kube-system | grep sealed-secrets
```

### 2. Create Production Secrets

```bash
# Navigate to scripts directory
cd helm-chart/ccf-api/scripts

# Generate sealed secrets (saves passwords securely)
./create-sealed-secrets.sh

# This creates: helm-chart/ccf-api/sealed-secrets.yaml
```

**IMPORTANT**: Save the generated passwords securely! You'll need them for:
- Database access
- User authentication
- API integration

### 3. Apply Sealed Secrets to Cluster

```bash
# Apply the sealed secrets (safe to commit to Git)
kubectl apply -f helm-chart/ccf-api/sealed-secrets.yaml

# Verify secrets were created
kubectl get secrets -n ccf-prod
```

### 4. Deploy with ArgoCD

```bash
# Apply ArgoCD application
kubectl apply -f argocd/ccf-api-prod.yaml

# Check deployment status
argocd app get ccf-api-prod
argocd app sync ccf-api-prod
```

### 5. Verify Deployment

```bash
# Check pods
kubectl get pods -n ccf-prod

# Check services
kubectl get svc -n ccf-prod

# Check HPA
kubectl get hpa -n ccf-prod

# View logs
kubectl logs -n ccf-prod -l app.kubernetes.io/name=ccf-api
```

## Security Considerations

### Secrets Management

1. **Sealed Secrets**: Encrypted at rest, safe to store in Git
2. **Rotation**: Rotate secrets quarterly or after personnel changes
3. **Access**: Limit who can decrypt sealed secrets

### Network Security

```yaml
# Network policies are enabled in production
networkPolicy:
  enabled: true
```

### Pod Security

- Runs as non-root user (UID 1000)
- Read-only root filesystem
- All capabilities dropped
- Seccomp profile enabled

## Monitoring and Maintenance

### Health Checks

```bash
# Check API health
curl https://api.ccf.yourdomain.com/health

# Check readiness
curl https://api.ccf.yourdomain.com/health/ready
```

### Scaling

The application auto-scales based on:
- CPU usage > 70%
- Memory usage > 80%
- Min replicas: 3
- Max replicas: 10

### Database Backups

```bash
# Create backup
kubectl exec -n ccf-prod deployment/ccf-api-postgresql -- \
  pg_dump -U ccf_prod ccf_prod > backup_$(date +%Y%m%d).sql
```

## Updating Secrets

### Method 1: Rotate All Secrets

```bash
# Generate new sealed secrets
cd helm-chart/ccf-api/scripts
./create-sealed-secrets.sh

# Apply new secrets
kubectl apply -f ../sealed-secrets.yaml

# Restart pods to pick up new secrets
kubectl rollout restart deployment/ccf-api-api -n ccf-prod
```

### Method 2: Update Specific Secret

```bash
# Create new secret
echo -n "new-password" | kubectl create secret generic temp-secret \
  --dry-run=client --from-file=password=/dev/stdin -o yaml | \
  kubeseal -o yaml > new-sealed-secret.yaml

# Apply it
kubectl apply -f new-sealed-secret.yaml
```

## Troubleshooting

### Sealed Secrets Issues

```bash
# Check sealed secrets controller logs
kubectl logs -n kube-system deployment/sealed-secrets-controller

# Verify secret unsealing
kubectl get sealedsecrets -A
```

### Database Connection Issues

```bash
# Check if secret exists
kubectl get secret ccf-api-secrets -n ccf-prod -o yaml

# Test database connection
kubectl exec -n ccf-prod deployment/ccf-api-api -- \
  psql postgresql://ccf_prod:$PASSWORD@ccf-api-postgresql:5432/ccf_prod
```

### ArgoCD Sync Issues

```bash
# Force refresh
argocd app get ccf-api-prod --refresh

# Check for differences
argocd app diff ccf-api-prod

# Manual sync with prune
argocd app sync ccf-api-prod --prune
```

## Disaster Recovery

### Backup Sealed Secrets Master Key

```bash
# Backup the sealed secrets private key (CRITICAL!)
kubectl get secret -n kube-system sealed-secrets-key -o yaml > sealed-secrets-key-backup.yaml

# Store this file securely (e.g., encrypted password manager)
```

### Restore Process

1. Restore sealed secrets controller and key
2. Apply sealed secrets
3. Deploy application with ArgoCD
4. Restore database from backup

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Deploy to Production
on:
  push:
    tags:
      - 'v*'

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Update ArgoCD App
        run: |
          argocd app set ccf-api-prod \
            --parameter api.image.tag=${{ github.ref_name }}
          argocd app sync ccf-api-prod --prune
```

## Cost Optimization

1. **Use spot instances** for non-critical workloads
2. **Enable cluster autoscaler** for node management
3. **Set resource requests** accurately to avoid over-provisioning
4. **Use persistent volume snapshots** instead of live replicas

## Compliance and Auditing

1. **Enable audit logging** in Kubernetes
2. **Use RBAC** to limit access
3. **Enable pod security policies**
4. **Regular security scans** of images
5. **Track all secret access** via audit logs

## Support

For production issues:
1. Check logs and metrics
2. Review this guide
3. Contact: devops@ccf.io