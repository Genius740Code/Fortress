# Fortress Container Images

This directory contains Dockerfiles for building container images of the Fortress secure database system.

## Available Images

### 1. Fortress Server
- **Path**: `crates/fortress-server/Dockerfile`
- **Purpose**: Production-ready REST API server
- **Port**: 8080
- **Health Check**: `/health` endpoint

### 2. Fortress CLI
- **Path**: `crates/fortress-cli/Dockerfile`
- **Purpose**: Command-line interface for database operations
- **Entry Point**: `fortress` command

### 3. Development Environment
- **Path**: `Dockerfile` (root)
- **Purpose**: Complete development environment with all components
- **Port**: 8080

## Building Images

```bash
# Build server image
docker build -t fortress-server:latest -f crates/fortress-server/Dockerfile .

# Build CLI image
docker build -t fortress-cli:latest -f crates/fortress-cli/Dockerfile .

# Build development image
docker build -t fortress:latest .
```

## Running Containers

### Server
```bash
docker run -d \
  --name fortress-server \
  -p 8080:8080 \
  -v fortress-data:/data \
  -e RUST_LOG=info \
  fortress-server:latest
```

### CLI
```bash
docker run -it --rm \
  -v fortress-data:/data \
  -e RUST_LOG=info \
  fortress-cli:latest \
  --help
```

## Environment Variables

- `RUST_LOG`: Logging level (debug, info, warn, error)
- `FORTRESS_DATA_DIR`: Data storage directory (default: /data)

## Volumes

- `/data`: Persistent storage for database files

## Security

- All containers run as non-root user `fortress`
- Minimal base images (debian:bookworm-slim)
- Health checks included for server
- SSL/TLS support for secure connections
