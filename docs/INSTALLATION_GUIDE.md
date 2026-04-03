# Fortress Installation Guide

Comprehensive installation instructions for all supported platforms and ecosystems.

## Table of Contents

- [System Requirements](#system-requirements)
- [Installation Methods](#installation-methods)
- [Package Manager Installation](#package-manager-installation)
- [Platform-Specific Installation](#platform-specific-installation)
- [Docker Installation](#docker-installation)
- [Kubernetes Installation](#kubernetes-installation)
- [Cloud Installation](#cloud-installation)
- [Development Installation](#development-installation)
- [Post-Installation Setup](#post-installation-setup)
- [Troubleshooting](#troubleshooting)

## System Requirements

### Minimum Requirements
- **CPU**: 2 cores (64-bit)
- **Memory**: 4GB RAM
- **Storage**: 10GB available space
- **Network**: Internet connection for package downloads

### Recommended Requirements
- **CPU**: 4+ cores (64-bit)
- **Memory**: 8GB+ RAM
- **Storage**: 50GB+ SSD storage
- **Network**: 1Gbps network for production

### Supported Operating Systems
- **Linux**: Ubuntu 20.04+, CentOS 8+, RHEL 8+, Debian 11+
- **macOS**: 11.0+ (Big Sur) or later
- **Windows**: Windows 10/11 (64-bit)
- **Container**: Docker 20.10+, Kubernetes 1.20+

## Installation Methods

Choose the installation method that best fits your needs:

| Method | Best For | Complexity | Updates |
|--------|-----------|-------------|----------|
| Pre-built Binaries | Quick start, production | Low | Manual |
| Package Managers | Development, CI/CD | Low | Automatic |
| Docker | Containers, microservices | Medium | Manual |
| Kubernetes | Production, scaling | High | Manual |
| Source Build | Development, customization | High | Manual |

## Package Manager Installation

### Rust/Cargo

#### Install from crates.io
```bash
# Install CLI tool
cargo install fortress-cli

# Install server binary
cargo install fortress-server

# Install core library
cargo add fortress-core
```

#### Install from Git Repository
```bash
# Latest stable version
cargo install --git https://github.com/fortress-security/fortress \
  --branch main fortress-cli

# Specific version
cargo install --git https://github.com/fortress-security/fortress \
  --tag v1.0.0 fortress-cli

# With features
cargo install --git https://github.com/fortress-security/fortress \
  --features "aws,azure,hsm" fortress-cli
```

#### Development Installation
```bash
git clone https://github.com/fortress-security/fortress.git
cd fortress

# Install from local source
cargo install --path crates/fortress-cli
cargo install --path crates/fortress-server
```

### Python/PyPI

#### Install from PyPI
```bash
# Basic installation
pip install fortress-db

# With development dependencies
pip install fortress-db[dev]

# With all optional dependencies
pip install fortress-db[all]

# Specific version
pip install fortress-db==1.0.0
```

#### Install from Source
```bash
git clone https://github.com/fortress-security/fortress.git
cd fortress/crates/fortress-python

# Install in development mode
pip install -e .

# Install with dependencies
pip install -e .[dev,all]
```

#### Virtual Environment Setup
```bash
# Create virtual environment
python -m venv fortress-env
source fortress-env/bin/activate  # Linux/macOS
# fortress-env\Scripts\activate  # Windows

# Install Fortress
pip install fortress-db[all]
```

### Node.js/npm

#### Install from npm Registry
```bash
# Install CLI globally
npm install -g fortress-cli

# Install as project dependency
npm install fortress-cli
npm install fortress-db

# Install with development dependencies
npm install fortress-cli --save-dev
```

#### Install from GitHub
```bash
# Latest version
npm install fortress-security/fortress

# Specific tag/branch
npm install fortress-security/fortress#v1.0.0
npm install fortress-security/fortress#main
```

#### Yarn Installation
```bash
# Global installation
yarn global add fortress-cli

# Project dependency
yarn add fortress-cli fortress-db
```

### Go

#### Install from Go Modules
```bash
# Add as dependency
go get github.com/fortress-security/fortress/fortress-go

# Install CLI tool
go install github.com/fortress-security/fortress/fortress-go/cmd/fortress-cli@latest

# Specific version
go install github.com/fortress-security/fortress/fortress-go/cmd/fortress-cli@v1.0.0
```

#### Development Installation
```bash
git clone https://github.com/fortress-security/fortress.git
cd fortress/crates/fortress-go

# Install from source
go install ./cmd/fortress-cli
```

## Platform-Specific Installation

### Linux

#### Ubuntu/Debian
```bash
# Update package index
sudo apt update

# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install Fortress
cargo install fortress-cli

# Or download pre-built binary
wget https://github.com/fortress-security/fortress/releases/latest/download/fortress-linux-amd64-latest
chmod +x fortress-linux-amd64-latest
sudo mv fortress-linux-amd64-latest /usr/local/bin/fortress
```

#### CentOS/RHEL/Fedora
```bash
# Install EPEL repository (if needed)
sudo dnf install epel-release

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install Fortress
cargo install fortress-cli

# Or download pre-built binary
wget https://github.com/fortress-security/fortress/releases/latest/download/fortress-linux-amd64-latest
chmod +x fortress-linux-amd64-latest
sudo mv fortress-linux-amd64-latest /usr/local/bin/fortress
```

#### Systemd Service Setup
```bash
# Create service file
sudo tee /etc/systemd/system/fortress.service > /dev/null <<EOF
[Unit]
Description=Fortress Security Platform
After=network.target

[Service]
Type=simple
User=fortress
Group=fortress
WorkingDirectory=/var/lib/fortress
ExecStart=/usr/local/bin/fortress server start
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl enable fortress
sudo systemctl start fortress
```

### macOS

#### Homebrew Installation
```bash
# Install Rust (if not installed)
brew install rust

# Install Fortress
cargo install fortress-cli

# Or download pre-built binary
curl -L "https://github.com/fortress-security/fortress/releases/latest/download/fortress-macos-amd64-latest" -o fortress
chmod +x fortress
sudo mv fortress /usr/local/bin/
```

#### MacPorts Installation
```bash
# Install Rust
sudo port install rust

# Install Fortress
cargo install fortress-cli
```

### Windows

#### Chocolatey Installation
```powershell
# Install Rust (if not installed)
choco install rust

# Install Fortress
cargo install fortress-cli

# Or download pre-built binary
Invoke-WebRequest -Uri "https://github.com/fortress-security/fortress/releases/latest/download/fortress-windows-amd64-latest.exe" -OutFile "fortress.exe"
Move-Item fortress.exe C:\Program Files\Fortress\
```

#### Scoop Installation
```powershell
# Install Rust (if not installed)
scoop install rustup

# Install Fortress
cargo install fortress-cli

# Or download pre-built binary
scoop bucket add fortress https://github.com/fortress-security/fortress-scoop
scoop install fortress
```

#### Windows Service Setup
```powershell
# Create Windows service
New-Service -Name "Fortress" -DisplayName "Fortress Security Platform" `
  -BinaryPathName "C:\Program Files\Fortress\fortress.exe server start" `
  -StartupType Automatic

# Start service
Start-Service -Name "Fortress"
```

## Docker Installation

### Docker Hub Images
```bash
# Pull official image
docker pull fortress-security/fortress:latest

# Pull specific version
docker pull fortress-security/fortress:v1.0.0

# Pull minimal image
docker pull fortress-security/fortress:alpine
```

### Basic Docker Usage
```bash
# Run with default configuration
docker run -d \
  --name fortress \
  -p 8080:8080 \
  -p 9090:9090 \
  fortress-security/fortress:latest

# Run with persistent storage
docker run -d \
  --name fortress \
  -p 8080:8080 \
  -p 9090:9090 \
  -v fortress_data:/var/lib/fortress \
  fortress-security/fortress:latest

# Run with custom configuration
docker run -d \
  --name fortress \
  -p 8080:8080 \
  -p 9090:9090 \
  -v $(pwd)/config.toml:/etc/fortress/config.toml \
  -v fortress_data:/var/lib/fortress \
  fortress-security/fortress:latest
```

### Docker Compose
```yaml
version: '3.8'

services:
  fortress:
    image: fortress-security/fortress:latest
    container_name: fortress
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "9090:9090"
    volumes:
      - fortress_data:/var/lib/fortress
      - ./config.toml:/etc/fortress/config.toml:ro
    environment:
      - FORTRESS_LOG_LEVEL=info
      - FORTRESS_ENCRYPTION_DEFAULT_ALGORITHM=aegis256
    networks:
      - fortress-network

  redis:
    image: redis:7-alpine
    container_name: fortress-redis
    restart: unless-stopped
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - fortress-network

volumes:
  fortress_data:
  redis_data:

networks:
  fortress-network:
    driver: bridge
```

## Kubernetes Installation

### Helm Installation
```bash
# Add Fortress Helm repository
helm repo add fortress https://helm.fortress-security.org
helm repo update

# Install Fortress
helm install my-fortress fortress/fortress \
  --namespace fortress \
  --create-namespace

# Install with custom values
helm install my-fortress fortress/fortress \
  --namespace fortress \
  --create-namespace \
  --values custom-values.yaml
```

### Kubernetes Manifests
```bash
# Create namespace
kubectl create namespace fortress

# Apply configuration
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
```

#### Example Deployment YAML
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fortress
  namespace: fortress
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
        image: fortress-security/fortress:v1.0.0
        ports:
        - containerPort: 8080
        - containerPort: 9090
        env:
        - name: FORTRESS_LOG_LEVEL
          value: "info"
        - name: FORTRESS_ENCRYPTION_DEFAULT_ALGORITHM
          value: "aegis256"
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        volumeMounts:
        - name: config
          mountPath: /etc/fortress
        - name: data
          mountPath: /var/lib/fortress
      volumes:
      - name: config
        configMap:
          name: fortress-config
      - name: data
        persistentVolumeClaim:
          claimName: fortress-data
```

## Cloud Installation

### AWS

#### EC2 Deployment
```bash
# Launch EC2 instance
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d316 \
  --instance-type t3.medium \
  --key-name my-key-pair \
  --security-group-ids sg-903004f8 \
  --subnet-id subnet-6e7f829e \
  --user-data file://install-fortress.sh

# install-fortress.sh content:
#!/bin/bash
yum update -y
yum install -y docker
systemctl start docker
systemctl enable docker
usermod -a -G docker ec2-user

# Install Fortress
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
cargo install fortress-cli

# Run Fortress
docker run -d \
  --name fortress \
  -p 8080:8080 \
  -p 9090:9090 \
  fortress-security/fortress:latest
```

#### ECS Deployment
```yaml
# ecs-task-definition.json
{
  "family": "fortress",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::account:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "fortress",
      "image": "fortress-security/fortress:v1.0.0",
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
      ]
    }
  ]
}
```

### Azure

#### Azure Container Instances
```bash
# Deploy to ACI
az container create \
  --resource-group myResourceGroup \
  --name fortress \
  --image fortress-security/fortress:v1.0.0 \
  --ports 8080 9090 \
  --environment-variables FORTRESS_LOG_LEVEL=info \
  --dns-name-label fortress-unique
```

#### Azure Kubernetes Service
```bash
# Create AKS cluster
az aks create \
  --resource-group myResourceGroup \
  --name myAKSCluster \
  --node-count 3 \
  --enable-addons monitoring \
  --generate-ssh-keys

# Get credentials
az aks get-credentials \
  --resource-group myResourceGroup \
  --name myAKSCluster

# Deploy Fortress
helm install my-fortress fortress/fortress \
  --namespace fortress \
  --create-namespace
```

### Google Cloud

#### Google Kubernetes Engine
```bash
# Create GKE cluster
gcloud container clusters create fortress-cluster \
  --num-nodes=3 \
  --zone=us-central1-a \
  --enable-autoscaling \
  --min-nodes=1 \
  --max-nodes=5

# Get credentials
gcloud container clusters get-credentials fortress-cluster \
  --zone=us-central1-a

# Deploy Fortress
helm install my-fortress fortress/fortress \
  --namespace fortress \
  --create-namespace
```

#### Cloud Run
```bash
# Deploy to Cloud Run
gcloud run deploy fortress \
  --image fortress-security/fortress:v1.0.0 \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --port 8080
```

## Development Installation

### Prerequisites
- **Rust**: 1.70.0 or later
- **Git**: For source code management
- **Build Tools**: Platform-specific build tools

### Source Installation
```bash
# Clone repository
git clone https://github.com/fortress-security/fortress.git
cd fortress

# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Build project
cargo build --release

# Run tests
cargo test

# Install CLI tool
cargo install --path crates/fortress-cli

# Install server binary
cargo install --path crates/fortress-server
```

### Development Environment Setup
```bash
# Install development dependencies
cargo install cargo-watch cargo-tarpaulin cargo-audit

# Set up pre-commit hooks
pip install pre-commit
pre-commit install

# Enable development features
cargo build --features "dev,debug,tracing"

# Run in development mode
cargo run --bin fortress-cli -- --help
```

### IDE Setup

#### VS Code
```json
// .vscode/settings.json
{
  "rust-analyzer.checkOnSave.command": "clippy",
  "rust-analyzer.cargo.features": "all",
  "files.associations": {
    "*.rs": "rust"
  }
}
```

#### IntelliJ IDEA
- Install Rust plugin
- Configure Rust toolchain
- Import project as Cargo project

## Post-Installation Setup

### Initial Configuration
```bash
# Initialize Fortress
fortress init

# Create admin user
fortress user create --username admin --role administrator

# Generate initial encryption keys
fortress key create --name master-key --algorithm aegis256

# Start services
fortress server start
```

### Configuration File
```toml
# /etc/fortress/config.toml
[server]
host = "0.0.0.0"
port = 8080
workers = 4

[database]
default_algorithm = "aegis256"
key_rotation_interval = "24h"

[encryption]
auto_rotation = true
key_derivation = "argon2id"

[logging]
level = "info"
format = "json"
file = "/var/log/fortress/fortress.log"

[cluster]
enabled = false
node_id = "node-1"
seed_nodes = []

[cache]
backend = "redis"
url = "redis://localhost:6379"
ttl = "1h"
```

### Environment Variables
```bash
# Server configuration
export FORTRESS_HOST=0.0.0.0
export FORTRESS_PORT=8080
export FORTRESS_WORKERS=4

# Database configuration
export FORTRESS_DATABASE_URL=postgresql://user:pass@localhost/fortress
export FORTRESS_DEFAULT_ALGORITHM=aegis256

# Security configuration
export FORTRESS_SECRET_KEY=your-secret-key
export FORTRESS_JWT_EXPIRY=24h

# Logging configuration
export FORTRESS_LOG_LEVEL=info
export FORTRESS_LOG_FORMAT=json
```

### Verification
```bash
# Check installation
fortress --version
fortress --help

# Test connectivity
curl http://localhost:8080/health

# Run diagnostics
fortress doctor

# View status
fortress status
```

## Troubleshooting

### Common Issues

#### Installation Fails
```bash
# Clear Rust cache
cargo clean

# Update Rust toolchain
rustup update stable

# Reinstall
cargo install fortress-cli --force
```

#### Permission Denied
```bash
# Fix permissions on Linux/macOS
sudo chown $USER:$USER ~/.fortress
chmod 755 ~/.fortress

# Fix permissions on Windows
icacls "C:\Program Files\Fortress" /grant Users:F
```

#### Port Already in Use
```bash
# Find process using port
sudo lsof -i :8080  # Linux/macOS
netstat -ano | findstr :8080  # Windows

# Kill process
sudo kill -9 <PID>  # Linux/macOS
taskkill /PID <PID> /F  # Windows
```

#### Docker Issues
```bash
# Pull latest image
docker pull fortress-security/fortress:latest

# Remove container and recreate
docker rm -f fortress
docker run -d --name fortress fortress-security/fortress:latest

# Check logs
docker logs fortress
```

### Getting Help

- **Documentation**: [Fortress Docs](https://docs.fortress-security.org)
- **Issues**: [GitHub Issues](https://github.com/fortress-security/fortress/issues)
- **Discussions**: [GitHub Discussions](https://github.com/fortress-security/fortress/discussions)
- **Community**: [Discord Server](https://discord.gg/fortress)

### Support Channels

- **Email**: support@fortress-security.org
- **Twitter**: @fortress_security
- **Mailing List**: fortress-users@lists.fortress-security.org

---

For more detailed information, see the [Configuration Reference](CONFIGURATION_REFERENCE.md) and [API Documentation](API_REFERENCE.md).
