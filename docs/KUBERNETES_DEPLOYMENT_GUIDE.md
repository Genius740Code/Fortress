# 🚀 Fortress Production Deployment Guide

## 📋 Overview

This guide provides comprehensive instructions for deploying Fortress in production environments using Kubernetes and Helm.

## 🎯 Prerequisites

### Required Tools
- **Kubernetes** v1.20+ with RBAC enabled
- **Helm** v3.8+
- **kubectl** configured for your target cluster
- **StorageClass** configured for persistent volumes

### Required Permissions
- Cluster admin permissions for initial setup
- Ability to create namespaces, RBAC roles, and storage classes

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Production Architecture                │
├─────────────────────────────────────────────────────────────┤
│  Load Balancer (Ingress)                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Fortress Pods (3+ replicas)                   │   │
│  │  ┌─────────────┐ ┌─────────────┐           │   │
│  │  │   Pod 1     │ │   Pod 2     │   ...     │   │
│  │  └─────────────┘ └─────────────┘           │   │
│  └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  Storage Layer                                          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │
│  │ PostgreSQL  │ │    Redis    │ │   Storage   │   │
│  │   (Primary) │ │   (Cache)   │ │   (PVC)    │   │
│  └─────────────┘ └─────────────┘ └─────────────┘   │
├─────────────────────────────────────────────────────────────┤
│  Monitoring & Observability                              │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐   │
│  │ Prometheus  │ │   Grafana   │ │    Loki    │   │
│  │ (Metrics)   │ │ (Dashboards)│ │  (Logs)    │   │
│  └─────────────┘ └─────────────┘ └─────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### 1. Add Helm Repository
```bash
helm repo add fortress https://helm.fortress.security
helm repo update
```

### 2. Create Namespace
```bash
kubectl create namespace fortress
kubectl label namespace fortress name=fortress
```

### 3. Install Dependencies
```bash
# Install PostgreSQL
helm install fortress-postgresql bitnami/postgresql \
  --namespace fortress \
  --set auth.postgresPassword=your-secure-password \
  --set auth.database=fortress \
  --set primary.persistence.size=100Gi

# Install Redis
helm install fortress-redis bitnami/redis \
  --namespace fortress \
  --set auth.password=your-redis-password \
  --set master.persistence.size=20Gi
```

### 4. Configure Secrets
```bash
# Generate secrets
JWT_SECRET=$(openssl rand -base64 32)
MASTER_KEY=$(openssl rand -base64 64)
DB_PASSWORD="your-secure-password"
API_KEY=$(openssl rand -hex 32)

# Create Kubernetes secret
kubectl create secret generic fortress-secrets \
  --namespace fortress \
  --from-literal=fortress-jwt-secret=$JWT_SECRET \
  --from-literal=fortress-master-key=$MASTER_KEY \
  --from-literal=fortress-db-password=$DB_PASSWORD \
  --from-literal=fortress-api-key=$API_KEY
```

### 5. Deploy Fortress
```bash
helm install fortress fortress/fortress \
  --namespace fortress \
  --set replicaCount=3 \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=fortress.yourdomain.com \
  --set backup.enabled=true \
  --set monitoring.serviceMonitor.enabled=true
```

## 🔧 Advanced Configuration

### Production Values
Create a `production-values.yaml` file:

```yaml
# Production Configuration
replicaCount: 5

image:
  repository: fortressdb/fortress
  tag: "v1.0.0"
  pullPolicy: IfNotPresent

# Resource Configuration
resources:
  limits:
    cpu: 2000m
    memory: 4Gi
    ephemeral-storage: 10Gi
  requests:
    cpu: 1000m
    memory: 2Gi
    ephemeral-storage: 5Gi

# Autoscaling
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 50
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80

# High Availability
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: app.kubernetes.io/name
            operator: In
            values:
            - fortress
        topologyKey: kubernetes.io/hostname

topologySpreadConstraints:
- maxSkew: 1
  topologyKey: topology.kubernetes.io/zone
  whenUnsatisfiable: DoNotSchedule

# Ingress Configuration
ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/rate-limit: "1000"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
  hosts:
    - host: fortress.yourdomain.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: fortress-tls
      hosts:
        - fortress.yourdomain.com

# Backup Configuration
backup:
  enabled: true
  schedule: "0 2 * * *"  # Daily at 2 AM
  format: "tar.gz"
  compression: true
  retentionDays: 90
  storageBackend: "s3"
  s3:
    bucket: "fortress-backups"
    region: "us-west-2"

# Monitoring
monitoring:
  serviceMonitor:
    enabled: true
    interval: 30s
    scrapeTimeout: 10s
  prometheusRule:
    enabled: true
    rules:
      - alert: FortressDown
        expr: up{job="fortress"} == 0
        for: 5m
        labels:
          severity: critical

# Security
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000

containerSecurityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
    - ALL
```

### Deploy with Custom Values
```bash
helm upgrade --install fortress fortress/fortress \
  --namespace fortress \
  --values production-values.yaml
```

## 🔒 Security Configuration

### Network Policies
```bash
kubectl apply -f - <<EOF
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
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: fortress
    ports:
    - protocol: TCP
      port: 5432
    - protocol: TCP
      port: 6379
EOF
```

### Pod Security Policy
```bash
kubectl apply -f - <<EOF
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: fortress-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
EOF
```

## 📊 Monitoring Setup

### Install Prometheus Stack
```bash
# Add Prometheus Helm repo
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Install Prometheus
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --set prometheus.prometheusSpec.podMonitorSelectorNilUsesHelmValues=false \
  --set prometheus.serviceMonitorSelectorNilUsesHelmValues=false
```

### Install Grafana
```bash
# Install Grafana
helm install grafana prometheus-community/grafana \
  --namespace monitoring \
  --set adminPassword=your-grafana-password

# Import Fortress dashboard
kubectl port-forward -n monitoring svc/grafana 3000:3000
# Visit http://localhost:3000 and import dashboard from docs/grafana-dashboard.json
```

## 🔧 Operations

### Scaling
```bash
# Scale replicas
kubectl scale deployment fortress-server --replicas=10 -n fortress

# Enable autoscaling
helm upgrade fortress fortress/fortress \
  --namespace fortress \
  --set autoscaling.enabled=true \
  --set autoscaling.minReplicas=5 \
  --set autoscaling.maxReplicas=50
```

### Updates
```bash
# Update Fortress version
helm upgrade fortress fortress/fortress \
  --namespace fortress \
  --set image.tag=v1.1.0

# Rollback
helm rollback fortress 1 --namespace fortress
```

### Backup and Restore
```bash
# List backups
kubectl exec -n fortress deployment/fortress-server -- fortress backup list

# Create manual backup
kubectl exec -n fortress deployment/fortress-server -- fortress backup create --name manual-backup

# Restore from backup
kubectl exec -n fortress deployment/fortress-server -- fortress backup restore --name backup-20240315-020000
```

## 🔍 Troubleshooting

### Common Issues

#### 1. Pod Pending Status
```bash
# Check pod events
kubectl describe pod -n fortress -l app.kubernetes.io/name=fortress

# Check resource quotas
kubectl describe namespace fortress
```

#### 2. Database Connection Issues
```bash
# Check database connectivity
kubectl exec -n fortress deployment/fortress-server -- nc -zv fortress-postgresql 5432

# Check database logs
kubectl logs -n fortress deployment/fortress-postgresql
```

#### 3. High Memory Usage
```bash
# Check resource usage
kubectl top pods -n fortress

# Check memory limits
kubectl get pod -n fortress -o yaml | grep -A 5 resources
```

### Health Checks
```bash
# Check pod health
kubectl get pods -n fortress -l app.kubernetes.io/name=fortress

# Check service health
kubectl get endpoints -n fortress

# Check application health
kubectl port-forward -n fortress svc/fortress-service 8080:8080
curl http://localhost:8080/health
```

## 📈 Performance Tuning

### Database Optimization
```yaml
# In values.yaml
database:
  connectionPoolSize: 50
  maxConnections: 200
  statementTimeout: "30s"
  queryTimeout: "10s"
```

### Cache Optimization
```yaml
# In values.yaml
cache:
  ttl: 7200
  maxSize: 10000
  evictionPolicy: "lru"
```

### Resource Optimization
```yaml
# In values.yaml
resources:
  limits:
    cpu: 4000m
    memory: 8Gi
  requests:
    cpu: 2000m
    memory: 4Gi
```

## 🛡️ Security Best Practices

### 1. Secrets Management
- Use external secret management (Vault, AWS Secrets Manager)
- Rotate secrets regularly
- Use least privilege access

### 2. Network Security
- Enable network policies
- Use TLS for all communications
- Implement rate limiting

### 3. Pod Security
- Run as non-root user
- Use read-only filesystem
- Drop all capabilities

### 4. Monitoring
- Enable comprehensive monitoring
- Set up alerting for critical metrics
- Regular security audits

## 📚 Additional Resources

- [API Reference](../API_REFERENCE.md)
- [Security Guide](../SECURITY.md)
- [Architecture Guide](../ARCHITECTURE.md)
- [Troubleshooting Guide](../TROUBLESHOOTING.md)

## 🆘 Support

For production support:
- 📧 Email: support@fortress.security
- 📖 Documentation: https://docs.fortress.security
- 🐛 Issues: https://github.com/fortress-security/fortress/issues
- 💬 Community: https://discord.gg/fortress

---

**🎉 Congratulations! Fortress is now deployed in production with enterprise-grade security, scalability, and monitoring.**
