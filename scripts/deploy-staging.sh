#!/bin/bash

# Fortress Staging Deployment Script
# This script deploys Fortress to the staging environment

set -euo pipefail

# Configuration
NAMESPACE="fortress-staging"
HELM_RELEASE="fortress-staging"
CHART_PATH="helm/fortress"
DOCKER_REGISTRY="ghcr.io"
IMAGE_NAME="fortressdb/fortress"
IMAGE_TAG="${1:-latest}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v helm &> /dev/null; then
        log_error "Helm is not installed"
        exit 1
    fi
    
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed"
        exit 1
    fi
    
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_info "Prerequisites check passed"
}

# Create namespace if it doesn't exist
create_namespace() {
    log_info "Creating namespace: $NAMESPACE"
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
}

# Add Helm repositories
add_helm_repos() {
    log_info "Adding Helm repositories..."
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo add grafana https://grafana.github.io/helm-charts
    helm repo update
}

# Deploy monitoring stack
deploy_monitoring() {
    log_info "Deploying monitoring stack..."
    
    # Deploy Prometheus
    helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
        --namespace monitoring \
        --create-namespace \
        --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.resources.requests.storage=50Gi \
        --set grafana.adminPassword=admin123 \
        --wait --timeout 10m
    
    log_info "Monitoring stack deployed"
}

# Deploy Fortress
deploy_fortress() {
    log_info "Deploying Fortress with tag: $IMAGE_TAG"
    
    helm upgrade --install "$HELM_RELEASE" "$CHART_PATH" \
        --namespace "$NAMESPACE" \
        --create-namespace \
        --set image.repository="$DOCKER_REGISTRY/$IMAGE_NAME" \
        --set image.tag="$IMAGE_TAG" \
        --set image.pullPolicy=Always \
        --set replicaCount=3 \
        --set ingress.enabled=true \
        --set ingress.className=nginx \
        --set ingress.hosts[0].host="fortress-staging.example.com" \
        --set ingress.tls[0].hosts[0]="fortress-staging.example.com" \
        --set ingress.tls[0].secretName="fortress-staging-tls" \
        --set autoscaling.enabled=true \
        --set autoscaling.minReplicas=2 \
        --set autoscaling.maxReplicas=10 \
        --set autoscaling.targetCPUUtilizationPercentage=70 \
        --set monitoring.serviceMonitor.enabled=true \
        --set monitoring.prometheusRule.enabled=true \
        --set networkPolicy.enabled=true \
        --set podDisruptionBudget.enabled=true \
        --set resources.requests.cpu=200m \
        --set resources.requests.memory=256Mi \
        --set resources.limits.cpu=500m \
        --set resources.limits.memory=512Mi \
        --wait --timeout 10m
    
    log_info "Fortress deployed successfully"
}

# Verify deployment
verify_deployment() {
    log_info "Verifying deployment..."
    
    # Wait for deployment to be ready
    kubectl rollout status deployment/"$HELM_RELEASE" -n "$NAMESPACE" --timeout=300s
    
    # Check pod status
    kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=fortress
    
    # Check services
    kubectl get services -n "$NAMESPACE"
    
    # Check ingress
    kubectl get ingress -n "$NAMESPACE"
    
    log_info "Deployment verification completed"
}

# Run smoke tests
run_smoke_tests() {
    log_info "Running smoke tests..."
    
    # Port forward to test locally
    kubectl port-forward -n "$NAMESPACE" svc/"$HELM_RELEASE" 8080:8080 &
    PORT_FORWARD_PID=$!
    
    # Wait for port forward to be ready
    sleep 10
    
    # Test health endpoint
    if curl -f http://localhost:8080/health; then
        log_info "Health check passed"
    else
        log_error "Health check failed"
        kill $PORT_FORWARD_PID
        exit 1
    fi
    
    # Test metrics endpoint
    if curl -f http://localhost:8080/metrics; then
        log_info "Metrics check passed"
    else
        log_warn "Metrics check failed (may not be enabled)"
    fi
    
    # Clean up port forward
    kill $PORT_FORWARD_PID
    
    log_info "Smoke tests completed"
}

# Show deployment info
show_deployment_info() {
    log_info "Deployment Information:"
    echo "Namespace: $NAMESPACE"
    echo "Helm Release: $HELM_RELEASE"
    echo "Image: $DOCKER_REGISTRY/$IMAGE_NAME:$IMAGE_TAG"
    echo ""
    echo "To access Fortress:"
    echo "kubectl port-forward -n $NAMESPACE svc/$HELM_RELEASE 8080:8080"
    echo "Then open http://localhost:8080"
    echo ""
    echo "To check logs:"
    echo "kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=fortress -f"
    echo ""
    echo "To check monitoring:"
    echo "kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80"
    echo "Then open http://localhost:3000 (admin/admin123)"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    # Kill any background processes
    jobs -p | xargs -r kill || true
}

# Set up cleanup trap
trap cleanup EXIT

# Main execution
main() {
    log_info "Starting Fortress staging deployment..."
    
    check_prerequisites
    create_namespace
    add_helm_repos
    deploy_monitoring
    deploy_fortress
    verify_deployment
    run_smoke_tests
    show_deployment_info
    
    log_info "Staging deployment completed successfully!"
}

# Run main function
main "$@"
