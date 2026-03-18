# 🚀 Fortress Security Platform - Deployment Guide

## 📋 Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Deployment Options](#deployment-options)
5. [Getting Started](#getting-started)
6. [Production Deployment](#production-deployment)
7. [Monitoring & Maintenance](#monitoring--maintenance)

---

## 🔧 System Requirements

### Minimum Requirements
- **CPU**: 2 cores, 2.4 GHz
- **Memory**: 4 GB RAM
- **Storage**: 10 GB available space
- **OS**: Linux (Ubuntu 20.04+, RHEL 8+), macOS 10.15+, Windows 10+

### Recommended Requirements
- **CPU**: 4+ cores, 3.0 GHz
- **Memory**: 8+ GB RAM
- **Storage**: 50+ GB SSD
- **Network**: 1 Gbps for distributed deployments

### Optional Dependencies
- **Redis**: 6.0+ (for distributed caching)
- **Memcached**: 1.6+ (for distributed caching)
- **PostgreSQL**: 12+ (for persistent storage)
- **Docker**: 20.10+ (for containerized deployment)

---

## 📦 Installation

### Option 1: Build from Source

```bash
# Clone the repository
git clone https://github.com/fortress-security/fortress.git
cd fortress

# Build all components
cargo build --release

# Install binaries
cargo install --path crates/fortress-cli
cargo install --path crates/fortress-server
```

### Option 2: Binary Installation

```bash
# Download latest release
wget https://github.com/fortress-security/fortress/releases/latest/download/fortress-linux-x64.tar.gz

# Extract and install
tar -xzf fortress-linux-x64.tar.gz
sudo cp fortress /usr/local/bin/
sudo cp fortress-server /usr/local/bin/
```

### Option 3: Docker Installation

```bash
# Pull the official image
docker pull fortress-security/fortress:latest

# Run with default configuration
docker run -p 8080:8080 -p 9090:9090 fortress-security/fortress:latest
```

---

## ⚙️ Configuration

### Basic Configuration

Create a configuration file `fortress.yaml`:

```yaml
# Fortress Configuration
server:
  host: "0.0.0.0"
  port: 8080
  workers: 4

# Database Configuration
database:
  type: "postgresql"
  host: "localhost"
  port: 5432
  name: "fortress"
  user: "fortress"
  password: "your-secure-password"

# Caching Configuration
cache:
  type: "hybrid"  # Options: in-memory, redis, memcached, hybrid
  redis:
    host: "localhost"
    port: 6379
  memcached:
    servers: ["localhost:11211"]

# Security Configuration
security:
  jwt_secret: "your-jwt-secret-key"
  encryption_key: "your-32-byte-encryption-key"
  rate_limit:
    requests_per_minute: 1000

# Logging Configuration
logging:
  level: "info"
  format: "json"
  file: "/var/log/fortress/fortress.log"
```

### Environment Variables

```bash
# Set environment variables
export FORTRESS_CONFIG_PATH="/etc/fortress/fortress.yaml"
export FORTRESS_LOG_LEVEL="info"
export FORTRESS_DATABASE_URL="postgresql://fortress:password@localhost/fortress"
export FORTRESS_REDIS_URL="redis://localhost:6379"
```

---

## 🚀 Deployment Options

### Option 1: Single Node Deployment

```bash
# Initialize Fortress
fortress init --config-path /etc/fortress/fortress.yaml

# Start the server
fortress-server --config-path /etc/fortress/fortress.yaml

# In another terminal, verify installation
fortress status
```

### Option 2: Cluster Deployment

```bash
# On node 1 (leader)
fortress-server --config-path /etc/fortress/fortress.yaml \
  --cluster-role leader \
  --cluster-id fortress-cluster \
  --node-id node-1 \
  --bind-addr 192.168.1.10:8080

# On node 2 (follower)
fortress-server --config-path /etc/fortress/fortress.yaml \
  --cluster-role follower \
  --cluster-id fortress-cluster \
  --node-id node-2 \
  --bind-addr 192.168.1.11:8080 \
  --join-addr 192.168.1.10:8080

# On node 3 (follower)
fortress-server --config-path /etc/fortress/fortress.yaml \
  --cluster-role follower \
  --cluster-id fortress-cluster \
  --node-id node-3 \
  --bind-addr 192.168.1.12:8080 \
  --join-addr 192.168.1.10:8080
```

### Option 3: Docker Compose Deployment

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  fortress-server:
    image: fortress-security/fortress:latest
    ports:
      - "8080:8080"
      - "9090:9090"
    environment:
      - FORTRESS_DATABASE_URL=postgresql://fortress:password@postgres:5432/fortress
      - FORTRESS_REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
    volumes:
      - ./config:/etc/fortress
      - ./logs:/var/log/fortress

  postgres:
    image: postgres:14
    environment:
      POSTGRES_DB: fortress
      POSTGRES_USER: fortress
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  postgres_data:
```

Deploy with:

```bash
docker-compose up -d
```

---

## 🎯 Getting Started

### 1. Initialize the System

```bash
# Create initial configuration
fortress config init

# Generate master encryption key
fortress key generate --name master-key --algorithm aes256-gcm

# Setup initial user
fortress user create --username admin --email admin@example.com --role admin
```

### 2. Test Basic Operations

```bash
# Test key generation
fortress key generate --name test-key --algorithm rsa2048

# Test encryption
echo "secret data" | fortress encrypt --key-id test-key > encrypted.dat

# Test decryption
fortress decrypt --key-id test-key --input encrypted.dat

# Test caching
fortress cache set --key test-value --data "cached data"
fortress cache get --key test-value
```

### 3. Verify API Access

```bash
# Get authentication token
TOKEN=$(fortress auth login --username admin --password your-password)

# Test API endpoint
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/api/v1/keys

# Test health endpoint
curl http://localhost:8080/health
```

---

## 🏭 Production Deployment

### Security Hardening

```bash
# Create dedicated user
sudo useradd -r -s /bin/false fortress

# Set proper permissions
sudo chown -R fortress:fortress /etc/fortress
sudo chmod 600 /etc/fortress/fortress.yaml

# Configure firewall
sudo ufw allow 8080/tcp
sudo ufw allow 9090/tcp
sudo ufw enable
```

### Systemd Service

Create `/etc/systemd/system/fortress.service`:

```ini
[Unit]
Description=Fortress Security Server
After=network.target

[Service]
Type=simple
User=fortress
Group=fortress
WorkingDirectory=/opt/fortress
ExecStart=/usr/local/bin/fortress-server --config-path /etc/fortress/fortress.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable fortress
sudo systemctl start fortress
sudo systemctl status fortress
```

### Load Balancer Configuration

Nginx configuration:

```nginx
upstream fortress_backend {
    server 192.168.1.10:8080;
    server 192.168.1.11:8080;
    server 192.168.1.12:8080;
}

server {
    listen 80;
    server_name fortress.example.com;

    location / {
        proxy_pass http://fortress_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /health {
        proxy_pass http://fortress_backend/health;
        access_log off;
    }
}
```

---

## 📊 Monitoring & Maintenance

### Health Monitoring

```bash
# Check system health
fortress health check

# Monitor cluster status
fortress cluster status

# View performance metrics
fortress metrics show

# Check cache performance
fortress cache stats
```

### Log Monitoring

```bash
# View real-time logs
tail -f /var/log/fortress/fortress.log

# Filter error logs
grep ERROR /var/log/fortress/fortress.log

# Monitor API access
grep "API request" /var/log/fortress/fortress.log
```

### Backup and Recovery

```bash
# Backup configuration
fortress backup create --name config-backup --type config

# Backup keys
fortress backup create --name key-backup --type keys

# Backup data
fortress backup create --name data-backup --type data

# Restore from backup
fortress backup restore --name config-backup
```

### Performance Tuning

```bash
# Tune cache settings
fortress cache tune --hit-ratio-target 0.95 --memory-limit 2GB

# Optimize database
fortress db optimize --vacuum --analyze

# Update performance thresholds
fortress config set performance.response_time_threshold_ms 100
```

---

## 🔧 Troubleshooting

### Common Issues

1. **Server won't start**
   ```bash
   # Check configuration
   fortress config validate
   
   # Check logs
   journalctl -u fortress -f
   ```

2. **Database connection failed**
   ```bash
   # Test database connectivity
   fortress db test-connection
   
   # Check database status
   fortress db status
   ```

3. **Cache not working**
   ```bash
   # Test cache connectivity
   fortress cache test
   
   # Check cache stats
   fortress cache stats
   ```

4. **Cluster issues**
   ```bash
   # Check cluster health
   fortress cluster health
   
   # View cluster members
   fortress cluster members
   ```

### Performance Issues

1. **High memory usage**
   ```bash
   # Check cache memory usage
   fortress cache memory-usage
   
   # Tune cache eviction
   fortress cache tune --eviction-policy lru
   ```

2. **Slow response times**
   ```bash
   # Check performance metrics
   fortress metrics performance
   
   # Enable detailed logging
   fortress config set logging.level debug
   ```

---

## 📚 Additional Resources

- **API Documentation**: http://localhost:8080/docs
- **Configuration Reference**: https://docs.fortress.security/configuration
- **Best Practices**: https://docs.fortress.security/best-practices
- **Community Support**: https://github.com/fortress-security/fortress/discussions
- **Professional Support**: support@fortress.security

---

## 🎉 Next Steps

1. **Review Security Settings**: Ensure all security configurations are properly set
2. **Set Up Monitoring**: Configure monitoring and alerting
3. **Test Disaster Recovery**: Verify backup and restore procedures
4. **Performance Testing**: Load test the system with expected workloads
5. **Security Audit**: Conduct security assessment and penetration testing

---

**🚀 Your Fortress security platform is now ready for production use!**

For additional support, visit our documentation at https://docs.fortress.security or contact our support team.
