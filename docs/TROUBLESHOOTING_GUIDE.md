# Fortress Troubleshooting Guide

## 🎯 Overview

This guide provides systematic procedures for diagnosing and resolving common Fortress issues. Always check the [Production Readiness Matrix](PRODUCTION_READINESS_MATRIX.md) to understand current limitations.

---

## 🚨 Emergency Procedures

### Service Completely Down

#### Quick Diagnosis
```bash
# 1. Check if Fortress is running
ps aux | grep fortress

# 2. Check port availability
netstat -tulpn | grep :8080

# 3. Check system resources
free -h
df -h
top

# 4. Check recent logs
journalctl -u fortress --since "1 hour ago" -n 50
```

#### Immediate Recovery
```bash
# Restart Fortress service
sudo systemctl restart fortress

# Or if running as container
docker restart fortress-container

# Check status after restart
fortress status --detailed
```

### Database Connection Issues

#### Symptoms
- "Connection refused" errors
- Timeout errors
- Authentication failures

#### Diagnosis
```bash
# Check database connectivity
fortress db test --connection

# Check database status
fortress db status

# Check configuration
fortress config show database

# Test network connectivity
nc -zv localhost 5432
```

#### Solutions
```bash
# Fix database configuration
fortress config set database.host localhost
fortress config set database.port 5432
fortress config set database.name fortress

# Restart with new config
fortress restart

# Reinitialize database if corrupted
fortress db reinit --backup-existing
```

---

## 🔧 Common Issues

### 1. Performance Problems

#### High Memory Usage

**Symptoms:**
- System becomes slow
- Out-of-memory errors
- Services being killed

**Diagnosis:**
```bash
# Check memory usage
fortress metrics memory

# Check process memory
ps aux --sort=-%mem | head -10

# Check for memory leaks
valgrind --leak-check=full fortress server

# Monitor memory trends
watch -n 5 'ps aux | grep fortress | grep -v grep'
```

**Solutions:**
```bash
# Reduce memory limits
fortress config set server.memory_limit 2GB

# Enable memory optimization
fortress config set performance.memory_optimization true

# Restart with optimized settings
fortress restart

# Add swap if needed (temporary)
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

#### High CPU Usage

**Symptoms:**
- System slow to respond
- High load averages
- Fan running constantly

**Diagnosis:**
```bash
# Check CPU usage
fortress metrics cpu

# Check load average
uptime

# Profile CPU usage
perf top -p $(pgrep fortress)

# Check for infinite loops
gdb -p $(pgrep fortress) -ex "thread apply all bt"
```

**Solutions:**
```bash
# Reduce worker threads
fortress config set server.worker_threads 4

# Enable CPU optimization
fortress config set performance.cpu_optimization true

# Limit concurrent operations
fortress config set server.max_concurrent_ops 100

# Restart
fortress restart
```

### 2. Encryption Issues

#### Key Rotation Failures

**Symptoms:**
- "Key rotation failed" errors
- Data access issues after rotation
- Inconsistent encryption state

**Diagnosis:**
```bash
# Check key status
fortress key list --status all

# Check rotation history
fortress key rotation-history

# Check for stuck rotations
fortress key rotation-status --all

# Verify key accessibility
fortress key test --all
```

**Solutions:**
```bash
# Force complete rotation
fortress key rotate --force --database dbname

# Rollback to previous key
fortress key rollback --database dbname --to-version previous

# Rebuild key metadata
fortress key rebuild-metadata --database dbname

# Verify data accessibility
fortress data verify --database dbname --sample-size 100
```

#### Encryption Algorithm Errors

**Symptoms:**
- "Unsupported algorithm" errors
- Data corruption during encryption/decryption
- Performance issues with specific algorithms

**Diagnosis:**
```bash
# Check available algorithms
fortress algorithm list

# Test each algorithm
fortress algorithm test --all

# Check current algorithm usage
fortress config show encryption

# Verify algorithm compatibility
fortress algorithm check-compatibility
```

**Solutions:**
```bash
# Switch to supported algorithm
fortress config set encryption.default_algorithm aegis256

# Migrate data to new algorithm
fortress algorithm migrate --from old_algo --to aegis256

# Verify migration
fortress data verify --algorithm aegis256

# Update all clients to use new algorithm
```

### 3. Network Issues

#### Connection Timeouts

**Symptoms:**
- "Connection timeout" errors
- Slow response times
- Intermittent connectivity

**Diagnosis:**
```bash
# Check network connectivity
ping -c 4 localhost
netstat -i

# Check port status
netstat -tulpn | grep :8080

# Check firewall rules
sudo iptables -L -n

# Test with different tools
curl -v --connect-timeout 5 http://localhost:8080/health
```

**Solutions:**
```bash
# Increase timeout values
fortress config set network.connect_timeout 30s
fortress config set network.read_timeout 60s

# Enable connection pooling
fortress config set network.connection_pool true

# Configure keepalive
fortress config set network.keepalive true

# Restart network services
fortress restart --network-only
```

#### SSL/TLS Issues

**Symptoms:**
- Certificate errors
- SSL handshake failures
- "HTTPS required" errors

**Diagnosis:**
```bash
# Check certificate validity
openssl x509 -in /path/to/cert.pem -text -noout

# Check certificate chain
openssl verify -CAfile ca.pem cert.pem

# Test SSL connection
openssl s_client -connect localhost:8443 -showcerts

# Check certificate expiration
openssl x509 -in cert.pem -noout -dates
```

**Solutions:**
```bash
# Generate new certificate
fortress cert generate --self-signed --localhost

# Install new certificate
fortress cert install --cert cert.pem --key key.pem

# Update SSL configuration
fortress config set network.ssl.enabled true
fortress config set network.ssl.cert_file /path/to/cert.pem
fortress config set network.ssl.key_file /path/to/key.pem

# Restart with SSL
fortress restart --ssl-only
```

### 4. Storage Issues

#### Disk Space Problems

**Symptoms:**
- "No space left on device" errors
- Write failures
- Service crashes

**Diagnosis:**
```bash
# Check disk usage
df -h

# Check Fortress data directory size
du -sh /var/lib/fortress

# Find large files
find /var/lib/fortress -type f -size +100M -ls

# Check disk health
smartctl -a /dev/sda
```

**Solutions:**
```bash
# Clean up old logs
fortress logs cleanup --older-than 30d

# Compact database
fortress db compact

# Archive old data
fortress archive --older-than 90d

# Move data to larger partition
sudo mv /var/lib/fortress /mnt/large_partition/fortress
sudo ln -s /mnt/large_partition/fortress /var/lib/fortress
```

#### Database Corruption

**Symptoms:**
- "Database corrupted" errors
- Data inconsistencies
- Crashes on startup

**Diagnosis:**
```bash
# Check database integrity
fortress db check --integrity

# Check for corrupted tables
fortress db check --tables

# Verify data consistency
fortress db verify --all

# Check transaction logs
fortress db logs --check
```

**Solutions:**
```bash
# Repair database
fortress db repair --backup-first

# Restore from backup
fortress restore --backup latest --force

# Reinitialize database
fortress db reinit --backup-corrupted

# Verify after repair
fortress db verify --all
```

---

## 🔍 Debugging Tools

### Logging Configuration

```bash
# Enable debug logging
fortress config set logging.level debug

# Enable specific module logging
fortress config set logging.modules encryption,storage,network

# Set log file location
fortress config set logging.file /var/log/fortress/debug.log

# Enable structured logging
fortress config set logging.format json

# Apply logging changes
fortress restart --logging-only
```

### Performance Profiling

```bash
# Enable performance profiling
fortress config set performance.profiling true

# Generate performance report
fortress profile --duration 60s --output profile.json

# Analyze slow operations
fortress profile --slow-operations --threshold 100ms

# Memory profiling
fortress profile --memory --output memory_profile.json

# CPU profiling
fortress profile --cpu --duration 30s
```

### Network Debugging

```bash
# Enable network debugging
fortress config set network.debug true

# Capture network traffic
tcpdump -i any -w network_capture.pcap port 8080

# Test network connectivity
fortress network test --endpoint all

# Check DNS resolution
nslookup localhost

# Trace network path
traceroute localhost
```

---

## 📊 Monitoring and Alerts

### Health Check Commands

```bash
# Comprehensive health check
fortress health --all

# Check specific components
fortress health --component database
fortress health --component encryption
fortress health --component network

# Continuous monitoring
watch -n 10 'fortress health --summary'
```

### Metrics Collection

```bash
# Export metrics
fortress metrics export --format prometheus --output metrics.txt

# Real-time metrics
fortress metrics watch --refresh 5s

# Performance metrics
fortress metrics performance --duration 60s

# Resource usage
fortress metrics resources --format table
```

### Alert Configuration

```bash
# Enable alerts
fortress config set alerts.enabled true

# Configure alert thresholds
fortress config set alerts.memory_threshold 80%
fortress config set alerts.cpu_threshold 90%
fortress config set alerts.disk_threshold 85%

# Set alert endpoints
fortress config set alerts.webhook https://hooks.slack.com/...
fortress config set alerts.email admin@example.com

# Test alert system
fortress alerts test --all
```

---

## 🆘 Getting Help

### Support Channels

```bash
# Generate support bundle
fortress support bundle --output support_bundle.tar.gz

# Check system information
fortress support info

# Export configuration
fortress config export --output config.json

# Export logs
fortress logs export --since 24h --output logs.tar.gz
```

### Community Resources

- **GitHub Issues**: [Report bugs and issues](https://github.com/Genius740Code/Fortress/issues)
- **Documentation**: [Complete documentation](https://github.com/Genius740Code/Fortress/docs)
- **Discussions**: [Community discussions](https://github.com/Genius740Code/Fortress/discussions)

### When to Escalate

**Escalate immediately if:**
- Complete service outage affecting production
- Data loss or corruption
- Security breach or vulnerability
- Critical performance degradation

**Escalate within 24 hours if:**
- Recurring errors that impact functionality
- Performance issues affecting users
- Configuration problems that prevent normal operation
- Backup or recovery failures

---

## 📋 Troubleshooting Checklist

### Before Opening an Issue

- [ ] Check [Production Readiness Matrix](PRODUCTION_READINESS_MATRIX.md) for known limitations
- [ ] Review this troubleshooting guide
- [ ] Check recent changes and updates
- [ ] Verify system requirements are met
- [ ] Collect relevant logs and metrics
- [ ] Test with minimal configuration
- [ ] Reproduce the issue consistently

### Information to Include

When reporting issues, include:
- Fortress version and build information
- Operating system and architecture
- Complete error messages and stack traces
- Steps to reproduce the issue
- Expected vs actual behavior
- Configuration files (redacted)
- Relevant logs and metrics
- System resources at time of issue

---

**Last Updated**: 2025-03-24  
**Version**: 0.1.0  
**Maintainer**: Fortress Development Team

> **Note**: This troubleshooting guide covers common issues with the current Alpha version. Some solutions may reference features that are not yet implemented. Always check the Production Readiness Matrix for current capabilities.
