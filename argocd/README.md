# ArgoCD Setup for CCF

This directory contains ArgoCD Application manifests for deploying CCF using GitOps.

## What is ArgoCD?

ArgoCD is a declarative, GitOps continuous delivery tool for Kubernetes. It:
- Monitors Git repositories for changes
- Automatically syncs Kubernetes resources to match Git
- Provides a UI to visualize and manage deployments
- Enables easy rollbacks and drift detection

## Access ArgoCD UI

1. **Port Forward** (already done):
   ```bash
   kubectl port-forward svc/argocd-server -n argocd 8090:443
   ```

2. **Access UI**: https://localhost:8090
   - Username: `admin`
   - Password: Get it with:
     ```bash
     kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
     ```

## Deploy CCF with ArgoCD

### Option 1: Using ArgoCD CLI

```bash
# Login to ArgoCD
argocd login localhost:8090 --insecure

# Create the application
argocd app create ccf \
  --repo https://github.com/compliance-framework/configuration-service \
  --path helm-chart/ccf \
  --dest-server https://kubernetes.default.svc \
  --dest-namespace default \
  --helm-value-files values-dev.yaml

# Sync the application
argocd app sync ccf
```

### Option 2: Using kubectl

```bash
# Apply the application manifest
kubectl apply -f ccf-application.yaml

# Check application status
kubectl get applications -n argocd
```

### Option 3: Using the UI

1. Go to https://localhost:8090
2. Click "New App"
3. Fill in:
   - App Name: `ccf`
   - Project: `default`
   - Sync Policy: `Automatic`
   - Repository: `https://github.com/compliance-framework/configuration-service`
   - Path: `helm-chart/ccf`
   - Cluster: `in-cluster`
   - Namespace: `default`
   - Values Files: `values-dev.yaml`

## GitOps Workflow

1. **Make changes** to Helm chart or values
2. **Commit and push** to Git
3. **ArgoCD detects** changes automatically
4. **Syncs** the cluster to match Git
5. **Verify** in ArgoCD UI

## ArgoCD Concepts

- **Application**: A group of Kubernetes resources defined in Git
- **Project**: Logical grouping of applications
- **Sync**: Deploy changes from Git to cluster
- **Refresh**: Check Git for changes
- **Prune**: Delete resources not in Git
- **Self-heal**: Revert manual changes in cluster

## Monitoring

Check application status:
```bash
argocd app get ccf
argocd app history ccf
```

## Rollback

```bash
# List revisions
argocd app history ccf

# Rollback to previous
argocd app rollback ccf
```

## Troubleshooting

1. **Check app status**:
   ```bash
   kubectl get applications -n argocd
   ```

2. **View sync status**:
   ```bash
   argocd app get ccf
   ```

3. **Check logs**:
   ```bash
   kubectl logs -n argocd deployment/argocd-server
   kubectl logs -n argocd deployment/argocd-repo-server
   ```

## Best Practices

1. **Use Git branches** for environments (dev, staging, prod)
2. **Protect main branch** with PR reviews
3. **Use semantic versioning** for Helm chart
4. **Monitor drift** between Git and cluster
5. **Enable notifications** for sync failures