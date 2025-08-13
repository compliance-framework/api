# CCF Kubernetes Deployment

Simple Kubernetes manifests for deploying CCF on minikube.

## Prerequisites

- minikube installed and running (`minikube start`)
- kubectl installed

## Quick Start

```bash
# Deploy everything
./deploy.sh

# Check deployment status
kubectl get pods
kubectl get services

# Access the API
minikube service ccf-api-service --url
# Or directly via NodePort: http://$(minikube ip):30080
```

## Manual Deployment

```bash
# Set minikube docker environment
eval $(minikube docker-env)

# Build the Docker image
docker build -t api:local --target production ..

# Apply manifests in order
kubectl apply -f configmap.yaml
kubectl apply -f postgres-deployment.yaml
kubectl apply -f postgres-service.yaml
kubectl apply -f ccf-deployment.yaml
kubectl apply -f ccf-service.yaml
```

## Post-Deployment Setup

### Port Forwarding

For better access on macOS with Docker driver:

```bash
# Forward CCF API
kubectl port-forward service/ccf-api-service 8080:8080 &

# Forward PostgreSQL (for imports)
kubectl port-forward service/postgres-service 5432:5432 &

# API is now accessible at http://localhost:8080
```

### Database Setup

1. **Run migrations:**
```bash
kubectl exec deployment/ccf-api -- /api migrate up
```

2. **Create a user:**
```bash
kubectl exec deployment/ccf-api -- /api users add \
  --email="admin@example.com" \
  --first-name="Admin" \
  --last-name="User" \
  --password="admin123"
```

### Authentication

After creating a user, you can authenticate via:

```bash
# Login endpoint
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "admin123"}'

# This returns a JWT token for authenticated requests
```

### Import OSCAL Data

With PostgreSQL port-forwarding active, run from the project root:

```bash
# Import SP 800-53 Catalog
CCF_DB_DRIVER=postgres CCF_DB_CONNECTION="host=localhost user=postgres password=postgres dbname=ccf port=5432 sslmode=disable" \
go run main.go oscal import -f testdata/sp800_53_catalog.json

# Import FedRAMP profiles
CCF_DB_DRIVER=postgres CCF_DB_CONNECTION="host=localhost user=postgres password=postgres dbname=ccf port=5432 sslmode=disable" \
go run main.go oscal import -f testdata/profile_fedramp_low.json -f testdata/profile_fedramp_moderate.json -f testdata/profile_fedramp_high.json

# Import component definitions
CCF_DB_DRIVER=postgres CCF_DB_CONNECTION="host=localhost user=postgres password=postgres dbname=ccf port=5432 sslmode=disable" \
go run main.go oscal import -f testdata/sp800-53-component.json -f testdata/sp800-53-component-aws.json

# Import sample SSP
CCF_DB_DRIVER=postgres CCF_DB_CONNECTION="host=localhost user=postgres password=postgres dbname=ccf port=5432 sslmode=disable" \
go run main.go oscal import -f testdata/fedramp_ssp.json
```

## Clean Up

```bash
kubectl delete -f .
```

## Files

- `configmap.yaml` - Environment variables for CCF
- `postgres-deployment.yaml` - PostgreSQL database
- `postgres-service.yaml` - Service to expose PostgreSQL internally
- `ccf-deployment.yaml` - CCF API deployment
- `ccf-service.yaml` - Service to expose CCF API (NodePort: 30080)
- `deploy.sh` - Automated deployment script