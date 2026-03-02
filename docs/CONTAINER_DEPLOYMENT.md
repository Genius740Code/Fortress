# Container Images and Kubernetes Deployment Guide

This document provides a quick reference for container deployment options.

## Quick Start

### Docker Compose (Development)

```bash
cd docker
docker-compose up -d
```

### Kubernetes (Production)

```bash
kubectl apply -f k8s/
```

### Helm (Production)

```bash
helm repo add fortress https://helm.fortress-db.com
helm install fortress fortress/fortress
```

## Container Images

- **Server**: `fortress-server:latest` - REST API server
- **CLI**: `fortress-cli:latest` - Command-line interface
- **Base**: `fortress:latest` - Complete development environment

## Key Files Created

### Docker Configuration
- `Dockerfile` - Base development image
- `crates/fortress-server/Dockerfile` - Production server image
- `crates/fortress-cli/Dockerfile` - CLI image
- `docker/docker-compose.yml` - Production stack
- `docker/docker-compose.dev.yml` - Development environment
- `docker/fortress-docker.sh` - Helper script

### Kubernetes Configuration
- `k8s/namespace.yaml` - Namespace definition
- `k8s/config.yaml` - ConfigMaps and Secrets
- `k8s/deployment.yaml` - Application deployment
- `k8s/service.yaml` - Service configuration
- `k8s/pvc.yaml` - Persistent storage

### Helm Charts
- `helm/fortress/` - Complete Helm chart
- `helm/fortress/values.yaml` - Default configuration
- `helm/fortress/templates/` - Kubernetes templates

### CI/CD Pipeline
- `.github/workflows/container-build.yml` - Automated builds
- `.github/workflows/release.yml` - Release automation

### Documentation
- `docs/DEPLOYMENT.md` - Comprehensive deployment guide
- `docker/README.md` - Docker-specific documentation

## Features Implemented

✅ **Multi-stage Docker builds** with minimal base images  
✅ **Multi-architecture support** (AMD64, ARM64)  
✅ **Security hardening** (non-root, read-only FS, capability dropping)  
✅ **Health checks** and monitoring integration  
✅ **Kubernetes manifests** with best practices  
✅ **Helm charts** for easy deployment  
✅ **CI/CD pipeline** with automated builds and security scanning  
✅ **Docker Compose** for local development  
✅ **Comprehensive documentation** and examples  

## Next Steps

1. Test the container builds locally
2. Set up container registry (GitHub Container Registry)
3. Configure Kubernetes cluster
4. Deploy using Helm charts
5. Set up monitoring and logging
6. Configure backup strategies

For detailed instructions, see `docs/DEPLOYMENT.md`.
