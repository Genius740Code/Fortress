# Kubernetes Deployment Guide

This guide covers production-ready Kubernetes deployment of Fortress with proper secrets management, security, and monitoring.

## 🚨 Current Status: Production Templates Available

**⚠️ Kubernetes manifests are production-ready but require proper secrets management**

## Prerequisites

### Kubernetes Cluster Requirements
- **Kubernetes Version**: 1.24+ (supports PodSecurity, seccompProfile)
- **Storage Class**: ReadWriteOnce persistent storage
- **Network**: LoadBalancer or Ingress controller
- **Security**: RBAC enabled, PSP/PSP policies

### Required Tools
- `kubectl` configured for your cluster
- `helm` (optional, for chart installation)
- `kubeseal` (for SealedSecrets)
- `vault` CLI (for Vault integration)

## Deployment Options

### Option 1: Local Manifests (Recommended)
```bash
# Clone repository
git clone https://github.com/Genius740Code/Fortress.git
cd Fortress

# Create namespace
kubectl apply -f k8s/namespace.yaml

# Deploy secrets (choose method)
kubectl apply -f k8s/secrets.yaml  # Basic secrets
# OR
kubectl apply -f k8s/sealed-secrets.yaml  # Encrypted secrets

# Deploy configuration
kubectl apply -f k8s/config.yaml

# Deploy storage
kubectl apply -f k8s/pvc.yaml

# Deploy application
kubectl apply -f k8s/deployment.yaml

# Deploy services
kubectl apply -f k8s/service.yaml
```

### Option 2: Helm Chart
```bash
# Add local Helm repository
helm repo add fortress ./helm/fortress
helm repo update

# Install with custom values
helm install my-fortress fortress/fortress \
  --namespace fortress \
  --create-namespace \
  --values k8s/helm-values.yaml
```

## Secrets Management

### Method 1: Kubernetes Secrets (Basic)

#### Create Secrets Manually
```bash
# Generate secrets
JWT_SECRET=$(openssl rand -base64 32)
MASTER_KEY=$(openssl rand -base64 32)
DB_PASSWORD=$(openssl rand -base64 16)
API_KEY=$(openssl rand -hex 16)

# Create secret file
cat > fortress-secrets.yaml << EOF
apiVersion: v1
kind: Secret
metadata:
  name: fortress-secrets
  namespace: fortress
type: Opaque
data:
  fortress-jwt-secret: $(echo -n $JWT_SECRET | base64)
  fortress-master-key: $(echo -n $MASTER_KEY | base64)
  fortress-db-password: $(echo -n $DB_PASSWORD | base64)
  fortress-api-key: $(echo -n $API_KEY | base64)
EOF

# Apply secret
kubectl apply -f fortress-secrets.yaml
```

#### Using kubectl Secret Command
```bash
# Create secrets directly
kubectl create secret generic fortress-secrets \
  --namespace=fortress \
  --from-literal=fortress-jwt-secret=$(openssl rand -base64 32) \
  --from-literal=fortress-master-key=$(openssl rand -base64 32) \
  --from-literal=fortress-db-password=$(openssl rand -base64 16) \
  --from-literal=fortress-api-key=$(openssl rand -hex 16)
```

### Method 2: SealedSecrets (Recommended for Production)

#### Install SealedSecrets Controller
```bash
# Add Bitnami repository
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Install SealedSecrets controller
helm install sealed-secrets bitnami/sealed-secrets \
  --namespace kube-system \
  --set secretName=sealed-secrets-key
```

#### Create SealedSecret
```bash
# Create regular secret
cat > fortress-secrets.yaml << EOF
apiVersion: v1
kind: Secret
metadata:
  name: fortress-secrets
  namespace: fortress
type: Opaque
data:
  fortress-jwt-secret: $(echo -n 'your-jwt-secret' | base64)
  fortress-master-key: $(echo -n 'your-master-key' | base64)
  fortress-db-password: $(echo -n 'your-db-password' | base64)
  fortress-api-key: $(echo -n 'your-api-key' | base64)
EOF

# Seal the secret
kubeseal --format yaml --cert-file sealed-secrets-cert.pem < fortress-secrets.yaml > fortress-sealed-secrets.yaml

# Apply sealed secret
kubectl apply -f fortress-sealed-secrets.yaml
```

### Method 3: HashiCorp Vault Integration

#### Install Vault
```bash
# Install Vault using Helm
helm repo add hashicorp https://helm.releases.hashicorp.com
helm install vault hashicorp/vault \
  --namespace vault \
  --create-namespace \
  --set server.dev.enabled=true \
  --set ui.enabled=true
```

#### Configure Vault for Fortress
```bash
# Enable KV secrets engine
vault secrets enable -path=fortress kv

# Create Fortress secrets
vault kv put fortress/production \
  jwt-secret="your-jwt-secret" \
  master-key="your-master-key" \
  db-password="your-db-password" \
  api-key="your-api-key"

# Create Kubernetes auth role
vault write auth/kubernetes/role/fortress-role \
  bound_service_account_names=fortress \
  bound_service_account_namespaces=fortress \
  policies=fortress-policy \
  ttl=24h
```

#### Deploy ExternalSecrets
```bash
# Install External Secrets Operator
helm repo add external-secrets https://charts.external-secrets.io
helm install external-secrets external-secrets/external-secrets \
  --namespace external-secrets \
  --create-namespace

# Apply ExternalSecret configuration
kubectl apply -f k8s/external-secrets.yaml
```

## Configuration Management

### ConfigMap Options

#### Static Configuration
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fortress-config
  namespace: fortress
data:
  fortress.toml: |
    [database]
    path = "/data/fortress.db"
    max_size = "10GB"
    cache_size = "256MB"
    
    [encryption]
    default_algorithm = "aes256gcm"
    key_rotation_interval = "168h"
    
    [api]
    rest_port = 8080
    enable_cors = true
```

#### Environment-Specific Configurations
```bash
# Development
kubectl apply -f k8s/config-dev.yaml

# Staging  
kubectl apply -f k8s/config-staging.yaml

# Production
kubectl apply -f k8s/config-prod.yaml
```

### Configuration Reloading
```yaml
# Enable automatic reloading
metadata:
  annotations:
    configmap.reloader.stakater.com/reload: "fortress-config"
    secret.reloader.stakater.com/reload: "fortress-secrets"
```

## Storage Configuration

### Persistent Volume Claims
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: fortress-data-pvc
  namespace: fortress
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 100Gi
  storageClassName: fast-ssd  # Use appropriate storage class
```

### Storage Classes
```bash
# List available storage classes
kubectl get storageclass

# Recommended storage classes for Fortress:
# - fast-ssd: High-performance SSD storage
# - encrypted-ssd: Encrypted at rest storage
# - backup-enabled: Storage with backup integration
```

### Backup Configuration
```yaml
# Enable backup in configuration
[storage.backup]
enabled = true
schedule = "0 2 * * *"  # Daily at 2 AM
retention = "30d"
bucket = "fortress-backups"
encryption = true
```

## Networking

### Service Configuration
```yaml
apiVersion: v1
kind: Service
metadata:
  name: fortress-service
  namespace: fortress
  labels:
    app.kubernetes.io/name: fortress
spec:
  type: ClusterIP  # Use LoadBalancer for external access
  ports:
    - name: http
      port: 80
      targetPort: 8080
      protocol: TCP
    - name: metrics
      port: 9090
      targetPort: 9090
      protocol: TCP
  selector:
    app.kubernetes.io/name: fortress
```

### Ingress Configuration
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: fortress-ingress
  namespace: fortress
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "1000"
spec:
  tls:
    - hosts:
        - fortress.example.com
      secretName: fortress-tls
  rules:
    - host: fortress.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: fortress-service
                port:
                  number: 80
```

## Security Configuration

### Pod Security Standards
```yaml
# Enhanced security context
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: false
        capabilities:
          drop:
          - ALL
          add:
          - NET_BIND_SERVICE
```

### Network Policies
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: fortress-network-policy
  namespace: fortress
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: fortress
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8080
        - protocol: TCP
          port: 9090
  egress:
    - to: []
      ports:
        - protocol: TCP
          port: 53    # DNS
        - protocol: TCP
          port: 443   # HTTPS
        - protocol: TCP
          port: 80    # HTTP
```

### RBAC Configuration
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: fortress
  namespace: fortress
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: fortress-role
  namespace: fortress
rules:
  - apiGroups: [""]
    resources: ["configmaps", "secrets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: fortress-rolebinding
  namespace: fortress
subjects:
  - kind: ServiceAccount
    name: fortress
    namespace: fortress
roleRef:
  kind: Role
  name: fortress-role
  apiGroup: rbac.authorization.k8s.io
```

## Monitoring and Observability

### Prometheus Monitoring
```yaml
apiVersion: v1
kind: ServiceMonitor
metadata:
  name: fortress-metrics
  namespace: fortress
  labels:
    app.kubernetes.io/name: fortress
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: fortress
  endpoints:
    - port: metrics
      interval: 30s
      path: /metrics
```

### Grafana Dashboard
```json
{
  "dashboard": {
    "title": "Fortress Monitoring",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(fortress_requests_total[5m])",
            "legendFormat": "{{method}} {{endpoint}}"
          }
        ]
      },
      {
        "title": "Encryption Operations",
        "type": "graph", 
        "targets": [
          {
            "expr": "rate(fortress_encryption_operations_total[5m])",
            "legendFormat": "{{algorithm}}"
          }
        ]
      }
    ]
  }
}
```

### Logging Configuration
```yaml
# Enable structured logging
[monitoring]
enable_tracing = true
log_level = "info"
log_format = "json"

# Jaeger integration
[monitoring.jaeger]
endpoint = "http://jaeger-collector:14268/api/traces"
service_name = "fortress"
sample_rate = 0.1
```

## Scaling and High Availability

### Horizontal Pod Autoscaler
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: fortress-hpa
  namespace: fortress
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: fortress-server
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
```

### Pod Disruption Budget
```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: fortress-pdb
  namespace: fortress
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: fortress
```

## Deployment Strategies

### Blue-Green Deployment
```bash
# Deploy blue version
kubectl apply -f k8s/deployment-blue.yaml

# Test blue version
kubectl port-forward service/fortress-blue 8080:8080

# Switch traffic to blue
kubectl patch service fortress-service -p '{"spec":{"selector":{"version":"blue"}}}'

# Deploy green version
kubectl apply -f k8s/deployment-green.yaml

# Test green version
kubectl port-forward service/fortress-green 8081:8080

# Switch traffic to green
kubectl patch service fortress-service -p '{"spec":{"selector":{"version":"green"}}}'

# Clean up blue version
kubectl delete deployment fortress-blue
```

### Canary Deployment
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: fortress-rollout
  namespace: fortress
spec:
  replicas: 5
  strategy:
    canary:
      steps:
      - setWeight: 20
      - pause: {duration: 10m}
      - setWeight: 40
      - pause: {duration: 10m}
      - setWeight: 60
      - pause: {duration: 10m}
      - setWeight: 80
      - pause: {duration: 10m}
  selector:
    matchLabels:
      app.kubernetes.io/name: fortress
  template:
    metadata:
      labels:
        app.kubernetes.io/name: fortress
        version: canary
    spec:
      # ... pod spec
```

## Troubleshooting

### Common Issues

#### Pod Not Starting
```bash
# Check pod status
kubectl get pods -n fortress

# Describe pod for details
kubectl describe pod -n fortress <pod-name>

# Check logs
kubectl logs -n fortress <pod-name>

# Check events
kubectl get events -n fortress --sort-by='.lastTimestamp'
```

#### Secrets Not Available
```bash
# Check secret exists
kubectl get secrets -n fortress

# Describe secret
kubectl describe secret fortress-secrets -n fortress

# Check secret mounting
kubectl exec -it <pod-name> -n fortress -- env | grep FORTRESS
```

#### Storage Issues
```bash
# Check PVC status
kubectl get pvc -n fortress

# Check storage class
kubectl get storageclass

# Check volume mounting
kubectl exec -it <pod-name> -n fortress -- df -h
```

#### Network Connectivity
```bash
# Check service endpoints
kubectl get endpoints -n fortress

# Test connectivity
kubectl exec -it <pod-name> -n fortress -- curl http://localhost:8080/health

# Check network policies
kubectl get networkpolicy -n fortress
```

### Performance Issues

#### High Memory Usage
```bash
# Check resource usage
kubectl top pods -n fortress

# Check resource limits
kubectl describe pod <pod-name> -n fortress | grep -A 10 Limits

# Increase memory limits if needed
kubectl patch deployment fortress-server -n fortress -p '{"spec":{"template":{"spec":{"containers":[{"name":"fortress-server","resources":{"limits":{"memory":"2Gi"}}}]}}}'
```

#### Slow Startup
```bash
# Check startup probe logs
kubectl describe pod <pod-name> -n fortress

# Adjust startup probe timing
kubectl patch deployment fortress-server -n fortress -p '{"spec":{"template":{"spec":{"containers":[{"name":"fortress-server","startupProbe":{"initialDelaySeconds":60}}]}}}'
```

## Maintenance

### Rolling Updates
```bash
# Update image
kubectl set image deployment/fortress-server \
  fortress-server=fortressdb/fortress:v0.1.1 \
  -n fortress

# Check rollout status
kubectl rollout status deployment/fortress-server -n fortress

# Rollback if needed
kubectl rollout undo deployment/fortress-server -n fortress
```

### Backup and Restore
```bash
# Backup data
kubectl exec -it <pod-name> -n fortress -- tar czf /tmp/backup.tar.gz /data

# Copy backup locally
kubectl cp <pod-name>:/tmp/backup.tar.gz ./fortress-backup-$(date +%Y%m%d).tar.gz -n fortress

# Restore data
kubectl cp ./fortress-backup.tar.gz <pod-name>:/tmp/restore.tar.gz -n fortress
kubectl exec -it <pod-name> -n fortress -- tar xzf /tmp/restore.tar.gz -C /data
```

---

## 🆘 Help and Support

- **Documentation**: [Fortress Docs](https://docs.fortress-db.com)
- **Issues**: [GitHub Issues](https://github.com/Genius740Code/Fortress/issues)
- **Community**: [Discussions](https://github.com/Genius740Code/Fortress/discussions)

**Note**: Always test deployments in staging before production. Monitor resource usage and performance closely after deployment.
