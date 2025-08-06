#!/bin/bash
set -e

# Script to create sealed secrets for CCF API production deployment

echo "🔐 Creating Sealed Secrets for CCF API Production"

# Check if kubeseal is installed
if ! command -v kubeseal &> /dev/null; then
    echo "❌ kubeseal is not installed. Please install it first:"
    echo "   brew install kubeseal"
    exit 1
fi

# Generate secure passwords if not provided
DB_PASSWORD=${DB_PASSWORD:-$(openssl rand -base64 32)}
JWT_SECRET=${JWT_SECRET:-$(openssl rand -base64 32)}
API_KEY=${API_KEY:-$(openssl rand -base64 32)}

echo "📝 Using the following values:"
echo "   DB_PASSWORD: [HIDDEN]"
echo "   JWT_SECRET: [HIDDEN]"
echo "   API_KEY: [HIDDEN]"

# Create namespace if it doesn't exist
kubectl create namespace ccf-prod --dry-run=client -o yaml | kubectl apply -f -

# Create the secret manifest
cat <<EOF > /tmp/ccf-api-secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: ccf-api-secrets
  namespace: ccf-prod
type: Opaque
stringData:
  database-password: "${DB_PASSWORD}"
  database-username: "ccf_prod"
  database-name: "ccf_prod"
  jwt-secret: "${JWT_SECRET}"
  api-key: "${API_KEY}"
---
apiVersion: v1
kind: Secret
metadata:
  name: ccf-api-postgresql
  namespace: ccf-prod
type: Opaque
stringData:
  postgres-password: "${DB_PASSWORD}"
  password: "${DB_PASSWORD}"
  username: "ccf_prod"
EOF

# Seal the secrets
echo "🔒 Sealing secrets..."
kubeseal --format yaml < /tmp/ccf-api-secrets.yaml > ../sealed-secrets.yaml

# Clean up temp file
rm -f /tmp/ccf-api-secrets.yaml

echo "✅ Sealed secrets created successfully!"
echo "   Output: helm-chart/ccf-api/sealed-secrets.yaml"
echo ""
echo "⚠️  IMPORTANT: Save these values securely for future reference:"
echo "   DB_PASSWORD=${DB_PASSWORD}"
echo "   JWT_SECRET=${JWT_SECRET}"
echo "   API_KEY=${API_KEY}"
echo ""
echo "📋 Next steps:"
echo "   1. Commit sealed-secrets.yaml to Git (it's safe!)"
echo "   2. Apply it: kubectl apply -f helm-chart/ccf-api/sealed-secrets.yaml"
echo "   3. Deploy with ArgoCD"