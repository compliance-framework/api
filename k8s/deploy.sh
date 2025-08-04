#!/bin/bash
set -e

echo "🚀 Deploying CCF to Kubernetes (minikube)"

# Check if minikube is running
if ! minikube status | grep -q "Running"; then
    echo "❌ Minikube is not running. Please start it with: minikube start"
    exit 1
fi

echo "📦 Building Docker image inside minikube..."
# Use minikube's Docker daemon
eval $(minikube docker-env)

# Build the image (using production target from Dockerfile)
docker build -t api:local --target production ..

echo "🔧 Applying Kubernetes manifests..."
# Apply all manifests
kubectl apply -f configmap.yaml
kubectl apply -f postgres-deployment.yaml
kubectl apply -f postgres-service.yaml

# Wait for postgres to be ready
echo "⏳ Waiting for PostgreSQL to be ready..."
kubectl wait --for=condition=available --timeout=60s deployment/postgres

# Deploy CCF API
kubectl apply -f ccf-deployment.yaml
kubectl apply -f ccf-service.yaml

echo "⏳ Waiting for CCF API to be ready..."
kubectl wait --for=condition=available --timeout=60s deployment/ccf-api

echo "✅ Deployment complete!"
echo ""
echo "📋 Status:"
kubectl get pods
echo ""
kubectl get services
echo ""
echo "🌐 To access CCF API:"
echo "   Run: minikube service ccf-api-service --url"
echo "   Or use: $(minikube ip):30080"