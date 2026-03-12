# Fortress Deployment Guide

## Overview

This guide covers deploying Fortress in various environments, from local development to production clusters. Fortress is designed to be container-ready and cloud-native.

## Prerequisites

### System Requirements

#### Minimum Requirements
- **CPU**: 2 cores
- **Memory**: 4GB RAM
- **Storage**: 20GB available space
- **Network**: 1Gbps recommended

#### Recommended Production Requirements
- **CPU**: 8+ cores
- **Memory**: 16GB+ RAM
- **Storage**: 100GB+ SSD
- **Network**: 10Gbps
- **High Availability**: 3+ nodes for clustering

### Software Dependencies
- Docker 20.10+ (for container deployment)
- Kubernetes 1.25+ (for K8s deployment)
- OpenSSL development libraries
- Rust 1.70+ (for source builds)

## Quick Start

### Docker Deployment (Recommended)

```bash
# Pull the latest image
docker pull fortressdb/fortress:latest

# Run with default settings
docker run -d \
  --name fortress \
  -p 8080:8080 \
  -v fortress_data:/var/lib/fortress \
  fortressdb/fortress:latest

# Run with custom configuration
docker run -d \
  --name fortress \
  -p 8080:8080 \
  -v $(pwd)/config.toml:/etc/fortress/config.toml \
  -v fortress_data:/var/lib/fortress \
  -e FORTRESS_LOG_LEVEL=info \
  fortressdb/fortress:latest
```

### Binary Installation

```bash
# Download the latest binary
curl -L "https://github.com/Genius740Code/Fortress/releases/latest/download/fortress-cli-$(uname -s)-$(uname -m).tar.gz" | tar -xz

# Install globally
sudo mv fortress /usr/local/bin/

# Create and start database
fortress create --name myapp --template enterprise
fortress start --port 8080
```

## Docker Deployment

### Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  fortress:
    image: fortressdb/fortress:latest
    container_name: fortress
    ports:
      - "8080:8080"
      - "8443:8443"
    volumes:
      - fortress_data:/var/lib/fortress
      - ./config:/etc/fortress
      - ./logs:/var/log/fortress
    environment:
      - FORTRESS_LOG_LEVEL=info
      - FORTRESS_ENCRYPTION_DEFAULT_ALGORITHM=aegis256
      - FORTRESS_KEY_ROTATION_INTERVAL=24h
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # Optional: PostgreSQL for metadata
  postgres:
    image: postgres:15
    container_name: fortress-postgres
    environment:
      POSTGRES_DB: fortress
      POSTGRES_USER: fortress
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  # Optional: Redis for caching
  redis:
    image: redis:7-alpine
    container_name: fortress-redis
    volumes:
      - redis_data:/data
    restart: unless-stopped

volumes:
  fortress_data:
    driver: local
  postgres_data:
    driver: local
  redis_data:
    driver: local
```

Start the services:

```bash
docker-compose up -d
```

### Production Docker Configuration

Create a production-ready `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  fortress:
    image: fortressdb/fortress:latest
    container_name: fortress-prod
    ports:
      - "8080:8080"
      - "8443:8443"
    volumes:
      - fortress_data:/var/lib/fortress
      - ./config/production.toml:/etc/fortress/config.toml:ro
      - ./certs:/etc/fortress/certs:ro
      - ./logs:/var/log/fortress
    environment:
      - FORTRESS_LOG_LEVEL=warn
      - FORTRESS_CONFIG_FILE=/etc/fortress/config.toml
    restart: always
    healthcheck:
      test: ["CMD", "curl", "-f", "https://localhost:8443/health"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 30s
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
      - /var/tmp

  nginx:
    image: nginx:alpine
    container_name: fortress-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - fortress
    restart: always

volumes:
  fortress_data:
    driver: local
```

## Kubernetes Deployment

### Basic Deployment

Create a namespace:

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: fortress
```

Create a ConfigMap:

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fortress-config
  namespace: fortress
data:
  config.toml: |
    [server]
    host = "0.0.0.0"
    port = 8080
    
    [database]
    default_algorithm = "aegis256"
    
    [encryption]
    key_rotation_interval = "24h"
    
    [logging]
    level = "info"
    format = "json"
```

Create a Deployment:

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
      containers:
      - name: fortress
        image: fortressdb/fortress:latest
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 8443
          name: https
        volumeMounts:
        - name: config
          mountPath: /etc/fortress
          readOnly: true
        - name: data
          mountPath: /var/lib/fortress
        - name: logs
          mountPath: /var/log/fortress
        env:
        - name: FORTRESS_CONFIG_FILE
          value: "/etc/fortress/config.toml"
        - name: FORTRESS_LOG_LEVEL
          value: "info"
        resources:
          requests:
            memory: "1Gi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: fortress-config
      - name: data
        persistentVolumeClaim:
          claimName: fortress-data
      - name: logs
        emptyDir: {}
```

Create a Service:

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: fortress-service
  namespace: fortress
spec:
  selector:
    app: fortress
  ports:
  - name: http
    port: 80
    targetPort: 8080
  - name: https
    port: 443
    targetPort: 8443
  type: ClusterIP
```

Create a Persistent Volume Claim:

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

Deploy to Kubernetes:

```bash
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f pvc.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
```

### Helm Chart Installation

Add the Fortress Helm repository:

```bash
helm repo add fortress https://helm.fortress-db.com
helm repo update
```

Install with default values:

```bash
helm install my-fortress fortress/fortress \
  --namespace fortress \
  --create-namespace
```

Install with custom values:

```bash
helm install my-fortress fortress/fortress \
  --namespace fortress \
  --create-namespace \
  --values values.yaml
```

Custom `values.yaml`:

```yaml
image:
  repository: fortressdb/fortress
  tag: latest
  pullPolicy: IfNotPresent

replicaCount: 3

service:
  type: ClusterIP
  port: 80
  httpsPort: 443

resources:
  requests:
    memory: "1Gi"
    cpu: "250m"
  limits:
    memory: "2Gi"
    cpu: "500m"

persistence:
  enabled: true
  size: 100Gi
  storageClass: fast-ssd

config:
  server:
    host: "0.0.0.0"
    port: 8080
  database:
    default_algorithm: "aegis256"
  encryption:
    key_rotation_interval: "24h"
  logging:
    level: "info"
    format: "json"

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
```

## Cloud Deployment

### AWS Deployment

#### ECS Deployment

Create an ECS task definition:

```json
{
  "family": "fortress",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::account:role/fortressTaskRole",
  "containerDefinitions": [
    {
      "name": "fortress",
      "image": "fortressdb/fortress:latest",
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "FORTRESS_LOG_LEVEL",
          "value": "info"
        }
      ],
      "mountPoints": [
        {
          "sourceVolume": "fortress-data",
          "containerPath": "/var/lib/fortress"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/fortress",
          "awslogs-region": "us-west-2",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ],
  "volumes": [
    {
      "name": "fortress-data",
      "efsVolumeConfiguration": {
        "fileSystemId": "fs-12345678",
        "rootDirectory": "/fortress"
      }
    }
  ]
}
```

#### CloudFormation Template

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Fortress Database Deployment'

Parameters:
  InstanceType:
    Type: String
    Default: t3.medium
    Description: EC2 instance type

  KeyName:
    Type: AWS::EC2::KeyPair::KeyName
    Description: EC2 Key Pair

Resources:
  FortressSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Fortress security group
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 8080
          ToPort: 8080
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0

  FortressInstance:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType: !Ref InstanceType
      KeyName: !Ref KeyName
      ImageId: ami-12345678
      SecurityGroups:
        - !Ref FortressSecurityGroup
      UserData:
        Fn::Base64: |
          #!/bin/bash
          yum update -y
          yum install -y docker
          service docker start
          usermod -a -G docker ec2-user
          docker run -d \
            --name fortress \
            -p 8080:8080 \
            -v /fortress-data:/var/lib/fortress \
            fortressdb/fortress:latest
```

### Azure Deployment

#### Azure Container Instance

```bash
# Create resource group
az group create --name fortress-rg --location eastus

# Deploy Fortress container
az container create \
  --resource-group fortress-rg \
  --name fortress \
  --image fortressdb/fortress:latest \
  --dns-name-label fortress-unique \
  --ports 8080 \
  --cpu 1 \
  --memory 2 \
  --environment-variables FORTRESS_LOG_LEVEL=info \
  --azure-file-volume-account-name fortressstorage \
  --azure-file-volume-account-key <storage-key> \
  --azure-file-volume-share-name fortress-data \
  --azure-file-volume-mount-path /var/lib/fortress
```

#### Azure Kubernetes Service (AKS)

```bash
# Create resource group
az group create --name fortress-rg --location eastus

# Create AKS cluster
az aks create \
  --resource-group fortress-rg \
  --name fortress-aks \
  --node-count 3 \
  --enable-addons monitoring \
  --generate-ssh-keys

# Get credentials
az aks get-credentials --resource-group fortress-rg --name fortress-aks

# Deploy using Helm
helm install my-fortress fortress/fortress \
  --namespace fortress \
  --create-namespace \
  --set azure.enabled=true \
  --set azure.resourceGroup=fortress-rg
```

### Google Cloud Deployment

#### Google Kubernetes Engine (GKE)

```bash
# Create cluster
gcloud container clusters create fortress-cluster \
  --zone us-central1-a \
  --num-nodes 3 \
  --machine-type n1-standard-2

# Get credentials
gcloud container clusters get-credentials fortress-cluster \
  --zone us-central1-a

# Deploy using Helm
helm install my-fortress fortress/fortress \
  --namespace fortress \
  --create-namespace \
  --set gcp.enabled=true \
  --set gcp.project=my-project
```

## Configuration Management

### Environment Variables

```bash
# Server configuration
FORTRESS_HOST=0.0.0.0
FORTRESS_PORT=8080
FORTRESS_TLS_ENABLED=true
FORTRESS_TLS_CERT_FILE=/etc/fortress/certs/server.crt
FORTRESS_TLS_KEY_FILE=/etc/fortress/certs/server.key

# Database configuration
FORTRESS_DB_HOST=localhost
FORTRESS_DB_PORT=5432
FORTRESS_DB_NAME=fortress
FORTRESS_DB_USER=fortress
FORTRESS_DB_PASSWORD=secure_password

# Encryption configuration
FORTRESS_ENCRYPTION_DEFAULT_ALGORITHM=aegis256
FORTRESS_KEY_ROTATION_INTERVAL=24h
FORTRESS_HSM_ENABLED=false

# Logging configuration
FORTRESS_LOG_LEVEL=info
FORTRESS_LOG_FORMAT=json
FORTRESS_LOG_FILE=/var/log/fortress/fortress.log

# Performance configuration
FORTRESS_MAX_CONNECTIONS=1000
FORTRESS_CONNECTION_TIMEOUT=30s
FORTRESS_READ_TIMEOUT=60s
FORTRESS_WRITE_TIMEOUT=60s
```

### Configuration File

Create a `config.toml` file:

```toml
[server]
host = "0.0.0.0"
port = 8080
tls_enabled = true
tls_cert_file = "/etc/fortress/certs/server.crt"
tls_key_file = "/etc/fortress/certs/server.key"

[database]
backend = "postgresql"
host = "localhost"
port = 5432
name = "fortress"
user = "fortress"
password = "secure_password"
max_connections = 100

[encryption]
default_algorithm = "aegis256"
key_rotation_interval = "24h"
auto_rotation = true

[key_management]
storage_backend = "local"
hsm_enabled = false

[logging]
level = "info"
format = "json"
file = "/var/log/fortress/fortress.log"
max_size = "100MB"
max_files = 10

[performance]
max_connections = 1000
connection_timeout = "30s"
read_timeout = "60s"
write_timeout = "60s"
worker_threads = 4

[audit]
enabled = true
log_file = "/var/log/fortress/audit.log"
rotation_interval = "1d"
retention_days = 365

[monitoring]
metrics_enabled = true
prometheus_enabled = true
health_check_interval = "30s"
```

## Security Configuration

### TLS/SSL Setup

#### Self-Signed Certificate (Development)

```bash
# Generate private key
openssl genrsa -out server.key 2048

# Generate certificate signing request
openssl req -new -key server.key -out server.csr

# Generate self-signed certificate
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
```

#### Let's Encrypt Certificate (Production)

```bash
# Install certbot
sudo apt-get install certbot

# Generate certificate
sudo certbot certonly --standalone -d fortress.example.com

# Copy certificates to Fortress directory
sudo cp /etc/letsencrypt/live/fortress.example.com/fullchain.pem /etc/fortress/certs/server.crt
sudo cp /etc/letsencrypt/live/fortress.example.com/privkey.pem /etc/fortress/certs/server.key
```

### Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 8080/tcp  # Fortress HTTP
sudo ufw allow 8443/tcp  # Fortress HTTPS
sudo ufw enable

# iptables
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
sudo iptables -A INPUT -j DROP
```

## Monitoring and Logging

### Prometheus Metrics

Configure Prometheus to scrape Fortress metrics:

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'fortress'
    static_configs:
      - targets: ['fortress:8080']
    metrics_path: '/metrics'
    scrape_interval: 10s
```

### Grafana Dashboard

Import the pre-built Fortress dashboard or create custom dashboards:

```json
{
  "dashboard": {
    "title": "Fortress Metrics",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(fortress_requests_total[5m])",
            "legendFormat": "{{method}}"
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
      }
    ]
  }
}
```

### Log Aggregation

#### ELK Stack

```yaml
# logstash.conf
input {
  beats {
    port => 5044
  }
}

filter {
  if [fields][service] == "fortress" {
    json {
      source => "message"
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "fortress-%{+YYYY.MM.dd}"
  }
}
```

## Backup and Recovery

### Automated Backup

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/backups/fortress"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="fortress_backup_${DATE}"

# Create backup directory
mkdir -p "${BACKUP_DIR}/${BACKUP_NAME}"

# Backup data
docker exec fortress tar -czf - /var/lib/fortress > "${BACKUP_DIR}/${BACKUP_NAME}/data.tar.gz"

# Backup configuration
cp /etc/fortress/config.toml "${BACKUP_DIR}/${BACKUP_NAME}/"

# Backup certificates
cp -r /etc/fortress/certs "${BACKUP_DIR}/${BACKUP_NAME}/"

# Create backup info
echo "Backup created: ${DATE}" > "${BACKUP_DIR}/${BACKUP_NAME}/backup_info.txt"

# Cleanup old backups (keep last 30 days)
find "${BACKUP_DIR}" -type d -name "fortress_backup_*" -mtime +30 -exec rm -rf {} \;
```

### Restore Procedure

```bash
#!/bin/bash
# restore.sh

BACKUP_DIR=$1
RESTORE_DIR="/tmp/fortress_restore"

if [ -z "$BACKUP_DIR" ]; then
    echo "Usage: $0 <backup_directory>"
    exit 1
fi

# Stop Fortress
docker stop fortress

# Create restore directory
mkdir -p "$RESTORE_DIR"

# Extract data
tar -xzf "${BACKUP_DIR}/data.tar.gz" -C "$RESTORE_DIR"

# Restore configuration
cp "${BACKUP_DIR}/config.toml" /etc/fortress/

# Restore certificates
cp -r "${BACKUP_DIR}/certs" /etc/fortress/

# Start Fortress
docker start fortress

echo "Restore completed from: $BACKUP_DIR"
```

## Troubleshooting

### Common Issues

#### Container Won't Start

```bash
# Check container logs
docker logs fortress

# Check container status
docker ps -a

# Debug with interactive shell
docker run -it --entrypoint /bin/sh fortressdb/fortress:latest
```

#### Connection Issues

```bash
# Check if port is listening
netstat -tlnp | grep 8080

# Test connectivity
curl -v http://localhost:8080/health

# Check firewall rules
sudo ufw status verbose
```

#### Performance Issues

```bash
# Check resource usage
docker stats fortress

# Monitor system resources
top -p $(pgrep fortress)

# Check disk space
df -h /var/lib/fortress
```

### Health Checks

```bash
# Basic health check
curl http://localhost:8080/health

# Detailed health check
curl http://localhost:8080/health?detailed=true

# Check metrics
curl http://localhost:8080/metrics
```

### Log Analysis

```bash
# View real-time logs
docker logs -f fortress

# Search for errors
docker logs fortress 2>&1 | grep ERROR

# Analyze access patterns
docker logs fortress 2>&1 | grep "POST /api/v1" | wc -l
```

This deployment guide provides comprehensive instructions for deploying Fortress in various environments with best practices for security, monitoring, and maintenance.
