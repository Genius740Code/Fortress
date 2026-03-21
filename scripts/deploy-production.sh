#!/bin/bash

# Fortress Production Deployment Script
# This script deploys Fortress to the production environment with safety checks

set -euo pipefail

# Configuration
NAMESPACE="fortress-production"
HELM_RELEASE="fortress-production"
CHART_PATH="helm/fortress"
DOCKER_REGISTRY="ghcr.io"
IMAGE_NAME="fortressdb/fortress"
IMAGE_TAG="${1:-latest}"
BACKUP_NAMESPACE="fortress-backup"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Safety checks
safety_checks() {
    log_step "Performing safety checks..."
    
    # Check if we're on the right branch/tag
    if [[ "$IMAGE_TAG" == "latest" ]]; then
        log_error "Cannot deploy 'latest' tag to production"
        exit 1
    fi
    
    # Check if production namespace exists
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_warn "Production namespace already exists"
        read -p "Do you want to continue with the upgrade? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Deployment cancelled"
            exit 0
        fi
    fi
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_info "Safety checks passed"
}

# Backup current deployment
backup_deployment() {
    log_step "Creating backup of current deployment..."
    
    # Create backup namespace
    kubectl create namespace "$BACKUP_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Backup current deployment if it exists
    if helm get values "$HELM_RELEASE" -n "$NAMESPACE" &> /dev/null; then
        log_info "Backing up current deployment values..."
        helm get values "$HELM_RELEASE" -n "$NAMESPACE" > "backup-values-$(date +%Y%m%d-%H%M%S).yaml"
        
        # Backup current PVCs
        kubectl get pvc -n "$NAMESPACE" -o yaml > "backup-pvcs-$(date +%Y%m%d-%H%M%S).yaml"
        
        log_info "Backup created"
    else
        log_info "No existing deployment to backup"
    fi
}

# Pre-deployment health check
pre_deployment_health_check() {
    log_step "Running pre-deployment health check..."
    
    # Check if there's an existing deployment
    if kubectl get deployment "$HELM_RELEASE" -n "$NAMESPACE" &> /dev/null; then
        log_info "Checking existing deployment health..."
        
        # Check if pods are ready
        READY_PODS=$(kubectl get deployment "$HELM_RELEASE" -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}')
        DESIRED_PODS=$(kubectl get deployment "$HELM_RELEASE" -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
        
        if [[ "$READY_PODS" != "$DESIRED_PODS" ]]; then
            log_error "Existing deployment is not healthy (ready: $READY_PODS, desired: $DESIRED_PODS)"
            exit 1
        fi
        
        log_info "Existing deployment is healthy"
    else
        log_info "No existing deployment found"
    fi
}

# Deploy Fortress with canary strategy
deploy_fortress() {
    log_step "Deploying Fortress with canary strategy..."
    
    # First, deploy canary (1 replica)
    log_info "Deploying canary (1 replica)..."
    helm upgrade --install "$HELM_RELEASE-canary" "$CHART_PATH" \
        --namespace "$NAMESPACE" \
        --set image.repository="$DOCKER_REGISTRY/$IMAGE_NAME" \
        --set image.tag="$IMAGE_TAG" \
        --set image.pullPolicy=Always \
        --set replicaCount=1 \
        --set ingress.enabled=false \
        --set autoscaling.enabled=false \
        --set monitoring.serviceMonitor.enabled=true \
        --set resources.requests.cpu=200m \
        --set resources.requests.memory=256Mi \
        --set resources.limits.cpu=500m \
        --set resources.limits.memory=512Mi \
        --wait --timeout 10m
    
    # Wait for canary to be ready
    kubectl rollout status deployment/"$HELM_RELEASE-canary" -n "$NAMESPACE" --timeout=300s
    
    # Run canary tests
    log_info "Running canary deployment tests..."
    if ! run_canary_tests; then
        log_error "Canary deployment tests failed"
        helm uninstall "$HELM_RELEASE-canary" -n "$NAMESPACE"
        exit 1
    fi
    
    # Deploy full production deployment
    log_info "Deploying full production deployment..."
    helm upgrade --install "$HELM_RELEASE" "$CHART_PATH" \
        --namespace "$NAMESPACE" \
        --create-namespace \
        --set image.repository="$DOCKER_REGISTRY/$IMAGE_NAME" \
        --set image.tag="$IMAGE_TAG" \
        --set image.pullPolicy=Always \
        --set replicaCount=5 \
        --set strategy.type=RollingUpdate \
        --set strategy.rollingUpdate.maxSurge=2 \
        --set strategy.rollingUpdate.maxUnavailable=1 \
        --set ingress.enabled=true \
        --set ingress.className=nginx \
        --set ingress.hosts[0].host="fortress.example.com" \
        --set ingress.tls[0].hosts[0]="fortress.example.com" \
        --set ingress.tls[0].secretName="fortress-production-tls" \
        --set autoscaling.enabled=true \
        --set autoscaling.minReplicas=3 \
        --set autoscaling.maxReplicas=50 \
        --set autoscaling.targetCPUUtilizationPercentage=70 \
        --set autoscaling.targetMemoryUtilizationPercentage=80 \
        --set verticalPodAutoscaling.enabled=true \
        --set monitoring.serviceMonitor.enabled=true \
        --set monitoring.prometheusRule.enabled=true \
        --set networkPolicy.enabled=true \
        --set podDisruptionBudget.enabled=true \
        --set podDisruptionBudget.minAvailable=2 \
        --set priorityClassName="fortress-high-priority" \
        --set resources.requests.cpu=500m \
        --set resources.requests.memory=1Gi \
        --set resources.limits.cpu=2000m \
        --set resources.limits.memory=4Gi \
        --set persistence.size=100Gi \
        --set logsPersistence.size=20Gi \
        --wait --timeout 15m
    
    # Clean up canary
    helm uninstall "$HELM_RELEASE-canary" -n "$NAMESPACE" || true
    
    log_info "Production deployment completed"
}

# Run canary tests
run_canary_tests() {
    log_info "Testing canary deployment..."
    
    # Port forward to canary
    kubectl port-forward -n "$NAMESPACE" deployment/"$HELM_RELEASE-canary" 8081:8080 &
    PORT_FORWARD_PID=$!
    
    # Wait for port forward
    sleep 10
    
    # Test health endpoint
    if curl -f http://localhost:8081/health; then
        log_info "Canary health check passed"
    else
        log_error "Canary health check failed"
        kill $PORT_FORWARD_PID
        return 1
    fi
    
    # Test basic functionality
    if curl -f -X POST http://localhost:8081/api/v1/databases \
         -H "Content-Type: application/json" \
         -d '{"name": "test-db", "description": "Test database"}'; then
        log_info "Canary functionality test passed"
    else
        log_error "Canary functionality test failed"
        kill $PORT_FORWARD_PID
        return 1
    fi
    
    # Clean up port forward
    kill $PORT_FORWARD_PID
    
    return 0
}

# Post-deployment verification
post_deployment_verification() {
    log_step "Running post-deployment verification..."
    
    # Wait for deployment to be ready
    kubectl rollout status deployment/"$HELM_RELEASE" -n "$NAMESPACE" --timeout=600s
    
    # Check pod status
    log_info "Checking pod status..."
    kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=fortress
    
    # Check services
    log_info "Checking services..."
    kubectl get services -n "$NAMESPACE"
    
    # Check ingress
    log_info "Checking ingress..."
    kubectl get ingress -n "$NAMESPACE"
    
    # Check HPA
    log_info "Checking HPA..."
    kubectl get hpa -n "$NAMESPACE"
    
    # Check VPA
    if kubectl get vpa -n "$NAMESPACE" &> /dev/null; then
        log_info "Checking VPA..."
        kubectl get vpa -n "$NAMESPACE"
    fi
    
    log_info "Post-deployment verification completed"
}

# Run smoke tests
run_smoke_tests() {
    log_step "Running production smoke tests..."
    
    # Port forward to production
    kubectl port-forward -n "$NAMESPACE" svc/"$HELM_RELEASE" 8080:8080 &
    PORT_FORWARD_PID=$!
    
    # Wait for port forward
    sleep 15
    
    # Test health endpoint
    if curl -f http://localhost:8080/health; then
        log_info "Production health check passed"
    else
        log_error "Production health check failed"
        kill $PORT_FORWARD_PID
        exit 1
    fi
    
    # Test metrics endpoint
    if curl -f http://localhost:8080/metrics; then
        log_info "Production metrics check passed"
    else
        log_warn "Production metrics check failed (may not be enabled)"
    fi
    
    # Test load
    log_info "Running load test..."
    for i in {1..100}; do
        curl -f http://localhost:8080/health > /dev/null || {
            log_error "Load test failed on request $i"
            kill $PORT_FORWARD_PID
            exit 1
        }
    done
    log_info "Load test passed (100 requests)"
    
    # Clean up port forward
    kill $PORT_FORWARD_PID
    
    log_info "Smoke tests completed"
}

# Rollback function
rollback() {
    log_error "Deployment failed, initiating rollback..."
    
    # Rollback to previous version
    if helm history "$HELM_RELEASE" -n "$NAMESPACE" | grep -q "deployed"; then
        PREVIOUS_REVISION=$(helm history "$HELM_RELEASE" -n "$NAMESPACE" | grep "deployed" | tail -2 | head -1 | awk '{print $1}')
        log_info "Rolling back to revision $PREVIOUS_REVISION"
        helm rollback "$HELM_RELEASE" "$PREVIOUS_REVISION" -n "$NAMESPACE"
    else
        log_error "No previous deployment found for rollback"
    fi
}

# Show deployment info
show_deployment_info() {
    log_info "Production Deployment Information:"
    echo "Namespace: $NAMESPACE"
    echo "Helm Release: $HELM_RELEASE"
    echo "Image: $DOCKER_REGISTRY/$IMAGE_NAME:$IMAGE_TAG"
    echo ""
    echo "To access Fortress:"
    echo "kubectl port-forward -n $NAMESPACE svc/$HELM_RELEASE 8080:8080"
    echo "Then open https://fortress.example.com"
    echo ""
    echo "To check logs:"
    echo "kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=fortress -f"
    echo ""
    echo "To check monitoring:"
    echo "kubectl port-forward -n monitoring svc/prometheus-grafana 3000:80"
    echo "Then open http://localhost:3000"
    echo ""
    echo "To check autoscaling:"
    echo "kubectl get hpa -n $NAMESPACE -w"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    # Kill any background processes
    jobs -p | xargs -r kill || true
}

# Set up cleanup trap
trap cleanup EXIT

# Set up error trap for rollback
trap 'rollback' ERR

# Main execution
main() {
    log_info "Starting Fortress production deployment..."
    log_info "Deploying image: $DOCKER_REGISTRY/$IMAGE_NAME:$IMAGE_TAG"
    
    safety_checks
    backup_deployment
    pre_deployment_health_check
    deploy_fortress
    post_deployment_verification
    run_smoke_tests
    show_deployment_info
    
    log_info "Production deployment completed successfully!"
}

# Run main function
main "$@"
