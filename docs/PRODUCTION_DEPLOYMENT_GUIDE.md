# Production Deployment Guide

## ⚠️ Important Notice

**Fortress is currently in Alpha stage (v0.1.0) and is NOT recommended for production deployments.** This guide is provided for future planning and testing purposes only.

See the [Production Readiness Matrix](PRODUCTION_READINESS_MATRIX.md) for current implementation status and production blockers.

---

## Overview

This guide provides step-by-step instructions for deploying Fortress in production environments. It covers infrastructure requirements, security configurations, monitoring setup, and operational best practices.

## Prerequisites

### System Requirements

#### Minimum Requirements
- **CPU**: 2 cores
- **Memory**: 4GB RAM
- **Storage**: 20GB SSD
- **Network**: 1Gbps
- **OS**: Linux (Ubuntu 20.04+, RHEL 8+), macOS 10.15+, Windows 10+

#### Recommended Production Requirements
- **CPU**: 4+ cores
- **Memory**: 8GB+ RAM
- **Storage**: 100GB+ SSD
- **Network**: 10Gbps
- **OS**: Linux (Ubuntu 22.04 LTS recommended)

#### Software Dependencies
- **Docker**: 20.10+
- **Kubernetes**: 1.24+ (for K8s deployment)
- **Helm**: 3.8+ (for Helm deployment)
- **Reverse Proxy**: Nginx 1.20+ or Traefik 2.8+

### Network Requirements

#### Port Configuration
- **8080**: Fortress API server
- **9090**: Metrics endpoint
- **8081**: Health check endpoint
- **8082**: Admin interface (if enabled)

#### Firewall Rules
```bash
# Allow Fortress API traffic
sudo ufw allow 8080/tcp

# Allow metrics (internal only)
sudo ufw allow from 10.0.0.0/8 to any port 9090

# Allow health checks
sudo ufw allow 8081/tcp
```

## Deployment Methods

### 1. Docker Deployment

#### Single Instance Deployment
```yaml
# docker-compose.yml
version: '3.8'

services:
  fortress:
    image: fortress-security/fortress:v0.1.0
    container_name: fortress
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "9090:9090"
      - "8081:8081"
    volumes:
      - fortress_data:/var/lib/fortress
      - fortress_logs:/var/log/fortress
      - ./config:/etc/fortress
    environment:
      - FORTRESS_LOG_LEVEL=info
      - FORTRESS_ENCRYPTION_DEFAULT_ALGORITHM=aegis256
      - FORTRESS_KEY_ROTATION_INTERVAL=24h
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8081/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - fortress_network

volumes:
  fortress_data:
    driver: local
  fortress_logs:
    driver: local

networks:
  fortress_network:
    driver: bridge
```

#### Production Docker Configuration
```bash
# Create production directories
sudo mkdir -p /opt/fortress/{config,data,logs}
sudo chown -R 1000:1000 /opt/fortress

# Create production config
cat > /opt/fortress/config/fortress.toml << EOF
[server]
host = "0.0.0.0"
port = 8080
workers = 4

[database]
path = "/var/lib/fortress/data"
default_algorithm = "aegis256"
backup_enabled = true
backup_interval = "6h"
backup_retention_days = 30

[encryption]
key_rotation_interval = "24h"
auto_rotation = true
hsm_enabled = false

[logging]
level = "info"
format = "json"
file = "/var/log/fortress/fortress.log"
max_size = "100MB"
max_files = 10

[metrics]
enabled = true
port = 9090
path = "/metrics"

[security]
tls_enabled = true
tls_cert_file = "/etc/ssl/certs/fortress.crt"
tls_key_file = "/etc/ssl/private/fortress.key"
rate_limit_enabled = true
rate_limit_requests_per_minute = 1000
EOF

# Deploy with production settings
docker-compose -f docker-compose.prod.yml up -d
```

### 2. Kubernetes Deployment

#### Namespace and RBAC
```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: fortress
  labels:
    name: fortress

---
# service-account.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: fortress
  namespace: fortress

---
# rbac.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: fortress
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints"]
  verbs: ["get", "list", "watch"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: fortress
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: fortress
subjects:
- kind: ServiceAccount
  name: fortress
  namespace: fortress
```

#### Deployment Configuration
```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fortress
  namespace: fortress
  labels:
    app: fortress
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fortress
  template:
    metadata:
      labels:
        app: fortress
    spec:
      serviceAccountName: fortress
      containers:
      - name: fortress
        image: fortress-security/fortress:v0.1.0
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 9090
          name: metrics
        - containerPort: 8081
          name: health
        env:
        - name: FORTRESS_LOG_LEVEL
          value: "info"
        - name: FORTRESS_ENCRYPTION_DEFAULT_ALGORITHM
          value: "aegis256"
        - name: FORTRESS_KEY_ROTATION_INTERVAL
          value: "24h"
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        volumeMounts:
        - name: data
          mountPath: /var/lib/fortress/data
        - name: config
          mountPath: /etc/fortress
        livenessProbe:
          httpGet:
            path: /health
            port: 8081
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8081
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: fortress-data
      - name: config
        configMap:
          name: fortress-config
```

#### Service Configuration
```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: fortress
  namespace: fortress
  labels:
    app: fortress
spec:
  selector:
    app: fortress
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  - name: metrics
    port: 9090
    targetPort: 9090
  type: ClusterIP

---
apiVersion: v1
kind: Service
metadata:
  name: fortress-health
  namespace: fortress
  labels:
    app: fortress
spec:
  selector:
    app: fortress
  ports:
  - name: health
    port: 8081
    targetPort: 8081
  type: ClusterIP
```

#### Persistent Storage
```yaml
# pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: fortress-data
  namespace: fortress
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 100Gi
  storageClassName: fast-ssd
```

#### Ingress Configuration
```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: fortress
  namespace: fortress
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "1000"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
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
            name: fortress
            port:
              number: 8080
```

### 3. Helm Deployment

#### Helm Chart Values
```yaml
# values.yaml
image:
  repository: fortress-security/fortress
  tag: v0.1.0
  pullPolicy: IfNotPresent

replicaCount: 3

service:
  type: ClusterIP
  port: 8080
  annotations: {}

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: fortress.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: fortress-tls
      hosts:
        - fortress.example.com

resources:
  limits:
    cpu: 1000m
    memory: 2Gi
  requests:
    cpu: 250m
    memory: 512Mi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80

persistence:
  enabled: true
  storageClass: fast-ssd
  size: 100Gi

config:
  logLevel: info
  encryptionAlgorithm: aegis256
  keyRotationInterval: 24h
  metricsEnabled: true

security:
  tlsEnabled: true
  rateLimitEnabled: true
  rateLimitRpm: 1000
```

#### Deploy with Helm
```bash
# Add Fortress Helm repository
helm repo add fortress https://fortress-security.github.io/helm-charts
helm repo update

# Install Fortress
helm install fortress fortress/fortress \
  --namespace fortress \
  --create-namespace \
  --values values.yaml

# Upgrade existing deployment
helm upgrade fortress fortress/fortress \
  --namespace fortress \
  --values values.yaml
```

## Security Configuration

### TLS/SSL Setup

#### Generate Self-Signed Certificate
```bash
# Create certificate directory
mkdir -p /opt/fortress/ssl

# Generate private key
openssl genrsa -out /opt/fortress/ssl/fortress.key 2048

# Generate certificate
openssl req -new -x509 -key /opt/fortress/ssl/fortress.key \
  -out /opt/fortress/ssl/fortress.crt -days 365 \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=fortress.example.com"

# Set permissions
chmod 600 /opt/fortress/ssl/fortress.key
chmod 644 /opt/fortress/ssl/fortress.crt
```

#### Let's Encrypt Certificate
```bash
# Install certbot
sudo apt-get update
sudo apt-get install certbot

# Generate certificate
sudo certbot certonly --standalone -d fortress.example.com

# Copy certificates
sudo cp /etc/letsencrypt/live/fortress.example.com/fullchain.pem /opt/fortress/ssl/fortress.crt
sudo cp /etc/letsencrypt/live/fortress.example.com/privkey.pem /opt/fortress/ssl/fortress.key
```

### Authentication Configuration

#### JWT Configuration
```toml
[authentication]
enabled = true
jwt_secret = "your-super-secret-jwt-key-here"
token_expiry = "24h"
refresh_token_expiry = "168h" # 7 days

[authentication.rate_limiting]
enabled = true
requests_per_minute = 1000
burst_size = 100
```

#### API Key Configuration
```toml
[api_keys]
enabled = true
default_expiry = "90d"
max_keys_per_user = 10

[api_keys.rate_limiting]
enabled = true
requests_per_minute = 5000
burst_size = 500
```

### Network Security

#### Firewall Configuration
```bash
# UFW Configuration
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH
sudo ufw allow ssh

# Allow Fortress
sudo ufw allow 8080/tcp
sudo ufw allow 443/tcp

# Allow monitoring (internal only)
sudo ufw allow from 10.0.0.0/8 to any port 9090

# Enable firewall
sudo ufw --force enable
```

#### Network Policies (Kubernetes)
```yaml
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: fortress-netpol
  namespace: fortress
spec:
  podSelector:
    matchLabels:
      app: fortress
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
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 9090
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
```

## Monitoring and Observability

### Prometheus Configuration

#### Prometheus Config
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'fortress'
    static_configs:
      - targets: ['fortress:9090']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'fortress-health'
    static_configs:
      - targets: ['fortress-health:8081']
    metrics_path: '/health'
    scrape_interval: 10s
```

#### Grafana Dashboard
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
            "legendFormat": "{{method}} {{status}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(fortress_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "singlestat",
        "targets": [
          {
            "expr": "rate(fortress_requests_total{status=~\"5..\"}[5m]) / rate(fortress_requests_total[5m])",
            "legendFormat": "Error Rate"
          }
        ]
      }
    ]
  }
}
```

### Log Aggregation

#### Fluentd Configuration
```yaml
# fluentd.conf
<source>
  @type tail
  path /var/log/fortress/fortress.log
  pos_file /var/log/fluentd/fortress.log.pos
  tag fortress
  format json
  time_format %Y-%m-%dT%H:%M:%S%.%NZ
</source>

<match fortress>
  @type elasticsearch
  host elasticsearch
  port 9200
  index_name fortress
  type_name _doc
</match>
```

### Health Checks

#### Health Check Endpoint
```bash
# Basic health check
curl -f http://localhost:8081/health

# Detailed health check
curl -f http://localhost:8081/health/detailed

# Readiness check
curl -f http://localhost:8081/ready
```

#### Health Check Configuration
```toml
[health]
enabled = true
port = 8081
path = "/health"
detailed_path = "/health/detailed"
readiness_path = "/ready"

[health.checks]
database = true
encryption = true
storage = true
memory = true
cpu = true

[health.thresholds]
memory_usage_percent = 80
cpu_usage_percent = 80
disk_usage_percent = 85
response_time_ms = 1000
```

## Backup and Recovery

### Backup Configuration

#### Automated Backups
```toml
[backup]
enabled = true
interval = "6h"
retention_days = 30
compression = true
encryption = true

[backup.storage]
type = "s3"
bucket = "fortress-backups"
region = "us-west-2"
access_key_id = "your-access-key"
secret_access_key = "your-secret-key"

[backup.notification]
email_enabled = true
email_to = "admin@example.com"
slack_webhook = "https://hooks.slack.com/your-webhook"
```

#### Manual Backup
```bash
# Create backup
fortress backup create --name "manual-backup-$(date +%Y%m%d)"

# List backups
fortress backup list

# Restore backup
fortress backup restore --name "manual-backup-20231201"
```

### Disaster Recovery

#### Recovery Procedures
```bash
# 1. Stop Fortress service
docker-compose down
kubectl scale deployment fortress --replicas=0

# 2. Restore data from backup
fortress backup restore --name "latest-backup"

# 3. Verify data integrity
fortress verify --all

# 4. Start Fortress service
docker-compose up -d
kubectl scale deployment fortress --replicas=3

# 5. Verify service health
curl -f http://localhost:8081/health
```

## Performance Tuning

### Database Optimization

#### Connection Pooling
```toml
[database]
max_connections = 100
min_connections = 10
connection_timeout = "30s"
idle_timeout = "300s"
max_lifetime = "3600s"
```

#### Caching Configuration
```toml
[cache]
enabled = true
type = "redis"
host = "redis"
port = 6379
max_connections = 50
ttl = "1h"
max_memory = "1GB"
```

### Application Performance

#### Worker Configuration
```toml
[server]
workers = 4
max_connections = 10000
keep_alive_timeout = "30s"
read_timeout = "30s"
write_timeout = "30s"
```

#### Memory Management
```toml
[memory]
max_heap_size = "2GB"
gc_threshold = 80
buffer_pool_size = "100MB"
```

## Troubleshooting

### Common Issues

#### Service Won't Start
```bash
# Check logs
docker logs fortress
kubectl logs deployment/fortress -n fortress

# Check configuration
fortress config validate

# Check ports
netstat -tlnp | grep 8080
```

#### High Memory Usage
```bash
# Check memory usage
docker stats
kubectl top pods -n fortress

# Check memory leaks
fortress profile memory

# Restart service
docker-compose restart
kubectl rollout restart deployment/fortress
```

#### Slow Performance
```bash
# Check metrics
curl http://localhost:9090/metrics

# Check database performance
fortress db stats

# Check network latency
ping fortress.example.com
```

### Debug Mode

#### Enable Debug Logging
```toml
[logging]
level = "debug"
format = "json"
file = "/var/log/fortress/debug.log"
```

#### Debug Commands
```bash
# Enable debug mode
fortress debug enable

# Get debug information
fortress debug info

# Disable debug mode
fortress debug disable
```

## Maintenance

### Regular Maintenance Tasks

#### Daily Tasks
- Check service health
- Review error logs
- Monitor resource usage
- Verify backups are running

#### Weekly Tasks
- Review performance metrics
- Check security updates
- Test backup restoration
- Audit access logs

#### Monthly Tasks
- Update Fortress version
- Review and rotate certificates
- Clean up old backups
- Performance tuning

### Update Procedures

#### Rolling Update
```bash
# Docker
docker-compose pull
docker-compose up -d

# Kubernetes
kubectl set image deployment/fortress fortress=fortress-security/fortress:v0.1.1
kubectl rollout status deployment/fortress

# Helm
helm upgrade fortress fortress/fortress --version 0.1.1
```

#### Zero-Downtime Update
```bash
# Enable maintenance mode
fortress maintenance enable --message "System update in progress"

# Perform update
kubectl set image deployment/fortress fortress=fortress-security/fortress:v0.1.1

# Wait for rollout
kubectl rollout status deployment/fortress

# Disable maintenance mode
fortress maintenance disable
```

---

## Support and Contact

### Getting Help
- **Documentation**: [Fortress Documentation](https://docs.fortress.security)
- **Community**: [GitHub Discussions](https://github.com/fortress-security/fortress/discussions)
- **Issues**: [GitHub Issues](https://github.com/fortress-security/fortress/issues)
- **Security**: [security@fortress.security](mailto:security@fortress.security)

### Enterprise Support
Enterprise support is planned for v1.0.0 release. Contact sales@fortress.security for information about enterprise support options.

---

**Last Updated**: 2025-03-24  
**Version**: v0.1.0  
**Status**: Alpha - Not Production Ready
