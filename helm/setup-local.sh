#!/bin/bash
# setup-local.sh - Set up Code Interpreter API on local Kubernetes (minikube or kind)
#
# Usage:
#   ./helm/setup-local.sh minikube   # Use minikube
#   ./helm/setup-local.sh kind       # Use kind

set -e

CLUSTER_TYPE="${1:-minikube}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚀 Code Interpreter API Local Kubernetes Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check KVM availability (informational only — kvmEnabled:false falls back to direct NsJail)
if [ -e /dev/kvm ]; then
    echo "✓ /dev/kvm available (microVM mode)"
else
    echo "ℹ /dev/kvm not found — will run in direct NsJail mode (kvmEnabled: false)"
fi

# Check prerequisites
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "❌ $1 is not installed. Please install it first."
        exit 1
    fi
    echo "✓ $1 found"
}

echo "📋 Checking prerequisites..."
check_command docker
check_command helm
check_command kubectl
check_command openssl
check_command base64
check_command "$CLUSTER_TYPE"
echo ""

# Start or check cluster
echo "📦 Setting up $CLUSTER_TYPE cluster..."
if [ "$CLUSTER_TYPE" = "minikube" ]; then
    if ! minikube status &> /dev/null; then
        echo "Starting minikube..."
        minikube start --cpus=4 --memory=8192 --driver=docker
    else
        echo "minikube is already running"
    fi
    # Point docker to minikube's daemon for building
    eval $(minikube docker-env)
elif [ "$CLUSTER_TYPE" = "kind" ]; then
    if ! kind get clusters | grep -q "codeapi"; then
        echo "Creating kind cluster..."
        kind create cluster --name codeapi
    else
        echo "kind cluster 'codeapi' already exists"
    fi
    kubectl cluster-info --context kind-codeapi
fi
echo ""

# Build images
echo "🔨 Building Docker images..."
cd "$PROJECT_DIR"

echo "Building codeapi-api..."
docker build -f service/Dockerfile.api -t codeapi-api:latest .

echo "Building codeapi-file-server..."
docker build --target production -f service/Dockerfile -t codeapi-file-server:latest .

echo "Building codeapi-tool-call-server..."
docker build --target production -f service/Dockerfile.tool-call-server -t codeapi-tool-call-server:latest .

echo "Building codeapi-worker..."
docker build -f service/Dockerfile.worker -t codeapi-worker:latest .

echo "Building codeapi-sandbox-runner..."
docker build --target sandbox-runner -f api/Dockerfile -t codeapi-sandbox-runner:latest .

echo "Building codeapi-egress-gateway..."
docker build -f service/Dockerfile.egress-gateway -t codeapi-egress-gateway:latest .

echo "Building codeapi-package-init..."
docker build -f docker/Dockerfile.package-init -t codeapi-package-init:latest .

echo ""

# Load images into cluster (only needed for kind)
if [ "$CLUSTER_TYPE" = "kind" ]; then
    echo "📤 Loading images into kind cluster..."
    kind load docker-image codeapi-api:latest --name codeapi
    kind load docker-image codeapi-file-server:latest --name codeapi
    kind load docker-image codeapi-tool-call-server:latest --name codeapi
    kind load docker-image codeapi-worker:latest --name codeapi
    kind load docker-image codeapi-sandbox-runner:latest --name codeapi
    kind load docker-image codeapi-egress-gateway:latest --name codeapi
    kind load docker-image codeapi-package-init:latest --name codeapi
    echo ""
fi

# Add Helm repos and update dependencies
echo "📚 Setting up Helm dependencies..."
helm repo add bitnami https://charts.bitnami.com/bitnami 2>/dev/null || true
helm repo update
helm dependency update ./helm/codeapi
echo ""

# Install or upgrade the release with per-run gateway credentials. Values stay in
# process memory and are never printed or written to disk.
echo "🎯 Deploying Code Interpreter API..."
UPGRADED_RELEASE=false
if helm status codeapi &> /dev/null; then
    UPGRADED_RELEASE=true
    echo "Upgrading existing release..."
    # Preserve the installed credentials. Rotating only the Secret would leave
    # existing pods on the old values until each restarts independently.
    INTERNAL_SERVICE_TOKEN="$(kubectl get secret codeapi-secrets -o jsonpath='{.data.codeapi-internal-service-token}' | base64 --decode)"
    EGRESS_GRANT_SECRET="$(kubectl get secret codeapi-secrets -o jsonpath='{.data.codeapi-egress-grant-secret}' | base64 --decode)"
    test -n "$INTERNAL_SERVICE_TOKEN"
    test -n "$EGRESS_GRANT_SECRET"
    case "$INTERNAL_SERVICE_TOKEN" in
        localdev-internal-service-token|changeme-in-production) INTERNAL_SERVICE_TOKEN="$(openssl rand -hex 32)" ;;
    esac
    case "$EGRESS_GRANT_SECRET" in
        localdev-egress-grant-secret-change-me-32b|changeme-egress-grant-secret-32-bytes-minimum) EGRESS_GRANT_SECRET="$(openssl rand -hex 32)" ;;
    esac
    HELM_GATEWAY_CREDENTIALS=(
        --set-string "internalServiceAuth.token=$INTERNAL_SERVICE_TOKEN"
        --set-string "egressGrant.secret=$EGRESS_GRANT_SECRET"
    )
    helm upgrade codeapi ./helm/codeapi --reuse-values -f ./helm/codeapi/values-local.yaml "${HELM_GATEWAY_CREDENTIALS[@]}"
else
    echo "Installing new release..."
    INTERNAL_SERVICE_TOKEN="${CODEAPI_INTERNAL_SERVICE_TOKEN:-$(openssl rand -hex 32)}"
    EGRESS_GRANT_SECRET="${CODEAPI_EGRESS_GRANT_SECRET:-$(openssl rand -hex 32)}"
    HELM_GATEWAY_CREDENTIALS=(
        --set-string "internalServiceAuth.token=$INTERNAL_SERVICE_TOKEN"
        --set-string "egressGrant.secret=$EGRESS_GRANT_SECRET"
    )
    helm install codeapi ./helm/codeapi -f ./helm/codeapi/values-local.yaml "${HELM_GATEWAY_CREDENTIALS[@]}"
fi
unset INTERNAL_SERVICE_TOKEN EGRESS_GRANT_SECRET HELM_GATEWAY_CREDENTIALS
echo ""

if [ "$UPGRADED_RELEASE" = true ]; then
    echo "♻️  Restarting deployments to load rebuilt images and the current Secret..."
    kubectl rollout restart deployment -l app.kubernetes.io/instance=codeapi
fi
unset UPGRADED_RELEASE

# Wait for package-init job (compiles Python from source — may be slow on first run)
if kubectl get job -l app.kubernetes.io/component=package-init 2>/dev/null | grep -q package-init; then
    echo "⏳ Waiting for package-init job (builds Python + pip packages)..."
    echo "   (This compiles Python from source on first run — subsequent runs are fast)"
    kubectl wait --for=condition=complete job -l app.kubernetes.io/component=package-init --timeout=900s || true
fi

# Wait for pods to be ready
echo "⏳ Waiting for pods to be ready..."
kubectl wait --for=condition=available deployment -l app.kubernetes.io/instance=codeapi --timeout=300s
echo ""

# Show status
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Setup complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
kubectl get pods -l app.kubernetes.io/instance=codeapi
echo ""
echo "To access the API:"
echo "  kubectl port-forward svc/codeapi-api 3112:3112"
echo ""
echo "Then test:"
echo "  curl http://localhost:3112/v1/health"
echo ""
echo "To view logs:"
echo "  kubectl logs -l app.kubernetes.io/component=api -f"
echo "  kubectl logs -l app.kubernetes.io/component=worker-sandbox -f"
echo ""
echo "To scale workers:"
echo "  kubectl scale deployment/codeapi-worker-sandbox --replicas=5"
echo ""
