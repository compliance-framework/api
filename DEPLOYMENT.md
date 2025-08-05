# CCF Deployment Guide

This guide helps you choose the right deployment method for your needs.

## Deployment Methods Comparison

| Method | Best For | Complexity | Production Ready |
|--------|----------|------------|------------------|
| **Docker Compose** | Local development | ⭐ Simple | ❌ No |
| **Plain Kubernetes** | Learning K8s | ⭐⭐ Medium | ⚠️  Basic |
| **Helm Chart** | Production | ⭐⭐⭐ Advanced | ✅ Yes |
| **ArgoCD** | GitOps/Enterprise | ⭐⭐⭐⭐ Complex | ✅ Yes |

## Method 1: Docker Compose
**When to use:** Local development, quick testing

```bash
docker compose up -d
```

✅ Pros:
- Simplest to start
- No Kubernetes knowledge needed
- Great for development

❌ Cons:
- Not for production
- No scaling
- Single machine only

## Method 2: Plain Kubernetes (k8s/)
**When to use:** Learning Kubernetes, simple deployments

```bash
cd k8s
./deploy.sh
```

✅ Pros:
- Good for learning Kubernetes
- Simple YAML files
- Easy to understand

❌ Cons:
- Manual configuration management
- Hard to manage multiple environments
- No versioning/rollback

## Method 3: Helm Chart
**When to use:** Production deployments, multiple environments

```bash
helm install my-ccf ./helm-chart/ccf -f values-prod.yaml
```

✅ Pros:
- Professional deployment method
- Easy environment management
- Built-in rollback
- Reusable and shareable

❌ Cons:
- Need to learn Helm
- More complex setup
- Overkill for simple tests

## Method 4: ArgoCD (GitOps)
**When to use:** Enterprise, continuous deployment

ArgoCD watches your Git repository and automatically deploys changes.

### Setting up ArgoCD with our Helm Chart:

1. **Install ArgoCD in your cluster:**
```bash
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
```

2. **Create an ArgoCD Application:**
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ccf
  namespace: argocd
spec:
  destination:
    namespace: ccf
    server: https://kubernetes.default.svc
  source:
    path: helm-chart/ccf
    repoURL: https://github.com/compliance-framework/configuration-service
    targetRevision: HEAD
    helm:
      valueFiles:
      - values-prod.yaml
  project: default
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

✅ Pros:
- Automatic deployment from Git
- Full audit trail
- Easy rollback
- Multi-cluster support

❌ Cons:
- Complex setup
- Another tool to manage
- Requires Git repository access

## Quick Decision Guide

**"I just want to try CCF locally"**
→ Use Docker Compose

**"I want to learn Kubernetes"**
→ Use Plain Kubernetes (k8s/)

**"I need a production deployment"**
→ Use Helm Chart

**"I need enterprise-grade CI/CD"**
→ Use Helm Chart + ArgoCD

## Next Steps

1. Choose your deployment method
2. Follow the specific README:
   - Docker: See main [README.md](README.md)
   - Kubernetes: See [k8s/README.md](k8s/README.md)
   - Helm: See [helm-chart/ccf/README.md](helm-chart/ccf/README.md)
3. Set up monitoring and logging
4. Configure backups for production