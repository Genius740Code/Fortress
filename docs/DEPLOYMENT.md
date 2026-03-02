# Container Images and Kubernetes Deployment

This document provides comprehensive guidance for building, deploying, and managing Fortress using container images and Kubernetes.

## Overview

Fortress provides container images for all its components and complete Kubernetes deployment manifests. The containerization strategy ensures:

- **Consistency**: Same runtime environment across development, staging, and production
- **Scalability**: Easy horizontal scaling with Kubernetes
- **Security**: Minimal base images and non-root execution
- **Portability**: Run on any container orchestration platform

## Container Images

### Available Images

| Image | Description | Tag Pattern |
|-------|-------------|-------------|
| `fortress-server` | Production REST API server | `latest`, `v1.0.0`, `main` |
| `fortress-cli` | Command-line interface | `latest`, `v1.0.0`, `main` |
| `fortress-base` | Complete development environment | `latest`, `v1.0.0`, `main` |

### Image Features

- **Multi-architecture**: Supports `linux/amd64` and `linux/arm64`
- **Minimal base**: Built from `debian:bookworm-slim`
- **Security**: Non-root user, read-only filesystem, dropped capabilities
- **Health checks**: Built-in liveness and readiness probes
- **Optimized**: Small image size with multi-stage builds

### Building Images Locally

```bash
# Build all images
docker build -t fortress:latest .
docker build -t fortress-server:latest -f crates/fortress-server/Dockerfile .
docker build -t fortress-cli:latest -f crates/fortress-cli/Dockerfile .

# Build for specific architecture
docker buildx build --platform linux/amd64,linux/arm64 -t fortress:latest .
```

## Docker Compose

### Development Environment

```bash
cd docker
docker-compose -f docker-compose.dev.yml up -d
```

### Production Stack

```bash
# Basic stack
docker-compose up -d

# With PostgreSQL backend
docker-compose --profile postgres up -d

# With Redis caching
docker-compose --profile redis up -d

# With monitoring (Prometheus + Grafana)
docker-compose --profile monitoring up -d

# Full stack
docker-compose --profile postgres,redis,monitoring up -d
```

### Helper Script

Use the provided helper script for common operations:

```bash
chmod +x docker/fortress-docker.sh

# Build images
./docker/fortress-docker.sh build

# Start services
./docker/fortress-docker.sh up --profile postgres,redis

# View logs
./docker/fortress-docker.sh logs --service fortress-server

# Get shell
./docker/fortress-docker.sh shell --service fortress-cli

# Clean up
./docker/fortress-docker.sh clean
```

## Kubernetes Deployment

### Quick Start

```bash
# Create namespace
kubectl apply -f k8s/namespace.yaml

# Deploy configuration
kubectl apply -f k8s/config.yaml

# Deploy storage
kubectl apply -f k8s/pvc.yaml

# Deploy application
kubectl apply -f k8s/deployment.yaml

# Expose service
kubectl apply -f k8s/service.yaml
```

### Configuration

#### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Logging level |
| `FORTRESS_SERVER_HOST` | `0.0.0.0` | Server bind address |
| `FORTRESS_SERVER_PORT` | `8080` | Server port |
| `FORTRESS_DATA_DIR` | `/data` | Data storage directory |

#### Secrets

Configure encryption and authentication secrets:

```bash
# Generate encryption key
ENCRYPTION_KEY=$(openssl rand -hex 32 | base64)

# Generate JWT secret
JWT_SECRET=$(openssl rand -hex 32 | base64)

# Create secret
kubectl create secret generic fortress-secrets \
  --from-literal=encryptionKey=$ENCRYPTION_KEY \
  --from-literal=jwtSecret=$JWT_SECRET \
  --namespace=fortress
```

### Scaling

```bash
# Scale to 5 replicas
kubectl scale deployment fortress-server --replicas=5 -n fortress

# Enable autoscaling
kubectl autoscale deployment fortress-server \
  --cpu-percent=70 \
  --min=3 \
  --max=10 \
  -n fortress
```

### Monitoring

The deployment includes Prometheus metrics:

```bash
# Access metrics
kubectl port-forward svc/fortress-server 8080:8080 -n fortress
curl http://localhost:8080/metrics
```

## Helm Charts

### Installation

```bash
# Add repository
helm repo add fortress https://helm.fortress-db.com
helm repo update

# Install
helm install fortress fortress/fortress --namespace fortress --create-namespace

# Upgrade
helm upgrade fortress fortress/fortress --namespace fortress

# Uninstall
helm uninstall fortress --namespace fortress
```

### Configuration

Create a values file:

```yaml
# fortress-values.yaml
replicaCount: 5
resources:
  requests:
    memory: "512Mi"
    cpu: "500m"
  limits:
    memory: "1Gi"
    cpu: "1000m"
persistence:
  size: 100Gi
  storageClass: "fast-ssd"
ingress:
  enabled: true
  hosts:
    - host: fortress.example.com
      paths:
        - path: /
          pathType: Prefix
```

Deploy with custom values:

```bash
helm install fortress fortress/fortress \
  --namespace fortress \
  --create-namespace \
  --values fortress-values.yaml
```

## CI/CD Pipeline

### Automated Builds

The GitHub Actions pipeline automatically:

1. **Tests**: Runs unit tests, format checks, and clippy
2. **Builds**: Creates multi-architecture container images
3. **Scans**: Performs security vulnerability scanning
4. **Publishes**: Pushes images to container registry
5. **Deploys**: Updates Helm charts and documentation

### Release Process

1. Create a tag: `git tag v1.0.0 && git push origin v1.0.0`
2. Pipeline automatically:
   - Builds and publishes container images
   - Creates GitHub release
   - Publishes crates to crates.io
   - Updates Helm charts

### Environment Promotion

- **main**: Production deployment
- **develop**: Staging deployment
- **pull requests**: Test builds only

## Security Considerations

### Container Security

- **Non-root execution**: All containers run as user `fortress` (UID/GID 1000)
- **Minimal base**: Uses `debian:bookworm-slim` to reduce attack surface
- **Read-only filesystem**: Runtime filesystem is mounted read-only
- **Capability dropping**: All Linux capabilities are dropped
- **Resource limits**: CPU and memory limits enforced

### Kubernetes Security

- **Network policies**: Restrict pod-to-pod communication
- **RBAC**: Minimal required permissions
- **Pod security policies**: Enforce security contexts
- **Secrets management**: Use Kubernetes secrets or external vault

### Image Scanning

- **Trivy**: Automated vulnerability scanning
- **SARIF**: Results uploaded to GitHub Security tab
- **Fail-fast**: Pipeline fails on high-severity vulnerabilities

## Troubleshooting

### Common Issues

1. **Pod fails to start**: Check resource limits and security contexts
2. **Storage issues**: Verify PVC binding and storage class availability
3. **Network problems**: Check service selectors and network policies
4. **Authentication failures**: Verify secret configuration

### Debug Commands

```bash
# Check pod status
kubectl get pods -n fortress

# View logs
kubectl logs -f deployment/fortress-server -n fortress

# Debug pod
kubectl exec -it deployment/fortress-server -n fortress -- /bin/bash

# Describe resources
kubectl describe pod -l app.kubernetes.io/name=fortress -n fortress
```

### Performance Tuning

1. **Resource allocation**: Adjust CPU/memory requests and limits
2. **Storage**: Use appropriate storage class for performance needs
3. **Networking**: Configure appropriate service types and ingress
4. **Monitoring**: Set up comprehensive monitoring and alerting

## Best Practices

1. **Version control**: Always use specific image tags, never `latest` in production
2. **Resource management**: Set appropriate requests and limits
3. **Backup strategy**: Regular backups of persistent data
4. **Monitoring**: Comprehensive logging and metrics collection
5. **Security updates**: Regular image updates and vulnerability scanning
6. **Testing**: Thorough testing in staging before production deployment

## Support

For container and deployment issues:

1. Check the [troubleshooting guide](#troubleshooting)
2. Review [GitHub Issues](https://github.com/Genius740Code/Fortress/issues)
3. Join our [Discord community](https://discord.gg/fortress)
4. Contact support@fortress-db.com for enterprise support
