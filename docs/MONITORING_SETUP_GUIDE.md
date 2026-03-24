# Monitoring Setup Guide

## ⚠️ Important Notice

**Fortress is currently in Alpha stage (v0.1.0) and monitoring features are under development.** This guide provides the planned monitoring setup for future production deployments.

See the [Production Readiness Matrix](PRODUCTION_READINESS_MATRIX.md) for current implementation status.

---

## Overview

This guide covers setting up comprehensive monitoring for Fortress deployments, including metrics collection, log aggregation, alerting, and dashboarding.

## Monitoring Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Fortress      │    │   Prometheus    │    │    Grafana      │
│   Application   │───▶│   Collection   │───▶│   Dashboards    │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     Logs        │    │    AlertManager │    │   Loki/ELK     │
│  (Fluentd)      │    │   Alerting     │    │  Log Storage    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Metrics Collection

### Fortress Metrics

#### Available Metrics
```bash
# Application metrics
fortress_requests_total{method, status, endpoint}
fortress_request_duration_seconds{method, endpoint}
fortress_active_connections
fortress_database_connections_active
fortress_cache_hits_total
fortress_cache_misses_total

# Security metrics
fortress_authentication_total{result, method}
fortress_authorization_total{result}
fortress_encryption_operations_total{operation, algorithm}
fortress_key_rotation_events_total{result}

# Business metrics
fortress_databases_total
fortress_tables_total
fortress_records_total{database, table}
fortress_storage_bytes_total{database}

# System metrics
fortress_memory_usage_bytes
fortress_cpu_usage_percent
fortress_disk_usage_bytes
fortress_network_bytes_sent_total
fortress_network_bytes_received_total
```

#### Metrics Configuration
```toml
[metrics]
enabled = true
port = 9090
path = "/metrics"
interval = "15s"
retention_days = 30

[metrics.labels]
environment = "production"
region = "us-west-2"
cluster = "main"

[metrics.custom]
business_metrics_enabled = true
security_metrics_enabled = true
performance_metrics_enabled = true
```

### Prometheus Setup

#### Prometheus Configuration
```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'production'
    region: 'us-west-2'

rule_files:
  - "fortress_rules.yml"
  - "alert_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  # Fortress Application Metrics
  - job_name: 'fortress'
    static_configs:
      - targets: ['fortress:9090']
    metrics_path: '/metrics'
    scrape_interval: 30s
    scrape_timeout: 10s

  # Fortress Health Checks
  - job_name: 'fortress-health'
    static_configs:
      - targets: ['fortress-health:8081']
    metrics_path: '/health'
    scrape_interval: 10s

  # Kubernetes Metrics
  - job_name: 'kubernetes-pods'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)

  # Node Exporter
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

  # Blackbox Exporter
  - job_name: 'blackbox'
    static_configs:
      - targets:
        - http://fortress.example.com/health
        - https://fortress.example.com/health
    metrics_path: /probe
    params:
      module: [http_2xx]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115
```

#### Fortress Recording Rules
```yaml
# fortress_rules.yml
groups:
  - name: fortress.rules
    interval: 30s
    rules:
      # Request rate
      - record: fortress:request_rate:5m
        expr: rate(fortress_requests_total[5m])

      # Error rate
      - record: fortress:error_rate:5m
        expr: rate(fortress_requests_total{status=~"5.."}[5m]) / rate(fortress_requests_total[5m])

      # 95th percentile response time
      - record: fortress:response_time_p95:5m
        expr: histogram_quantile(0.95, rate(fortress_request_duration_seconds_bucket[5m]))

      # Database connection utilization
      - record: fortress:db_connection_utilization
        expr: fortress_database_connections_active / fortress_database_connections_max

      # Cache hit rate
      - record: fortress:cache_hit_rate:5m
        expr: rate(fortress_cache_hits_total[5m]) / (rate(fortress_cache_hits_total[5m]) + rate(fortress_cache_misses_total[5m]))

      # Authentication success rate
      - record: fortress:auth_success_rate:5m
        expr: rate(fortress_authentication_total{result="success"}[5m]) / rate(fortress_authentication_total[5m])

      # Storage growth rate
      - record: fortress:storage_growth_rate:1h
        expr: rate(fortress_storage_bytes_total[1h])
```

### AlertManager Configuration

#### AlertManager Setup
```yaml
# alertmanager.yml
global:
  smtp_smarthost: 'smtp.example.com:587'
  smtp_from: 'alerts@fortress.example.com'
  smtp_auth_username: 'alerts@fortress.example.com'
  smtp_auth_password: 'your-smtp-password'

route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'default'
  routes:
    - match:
        severity: critical
      receiver: 'critical-alerts'
      group_wait: 5s
      repeat_interval: 30m
    - match:
        severity: warning
      receiver: 'warning-alerts'
      repeat_interval: 2h

receivers:
  - name: 'default'
    email_configs:
      - to: 'team@example.com'
        subject: '[Fortress] {{ .GroupLabels.alertname }}'
        body: |
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          {{ end }}

  - name: 'critical-alerts'
    email_configs:
      - to: 'oncall@example.com'
        subject: '[CRITICAL] Fortress Alert: {{ .GroupLabels.alertname }}'
        body: |
          CRITICAL ALERT DETECTED
          
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          Severity: {{ .Labels.severity }}
          Time: {{ .StartsAt }}
          {{ end }}
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#alerts'
        title: 'Fortress Critical Alert'
        text: |
          {{ range .Alerts }}
          {{ .Annotations.summary }}
          {{ .Annotations.description }}
          {{ end }}

  - name: 'warning-alerts'
    email_configs:
      - to: 'team@example.com'
        subject: '[WARNING] Fortress Alert: {{ .GroupLabels.alertname }}'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#warnings'
        title: 'Fortress Warning'
```

#### Alert Rules
```yaml
# alert_rules.yml
groups:
  - name: fortress.alerts
    rules:
      # Service Down
      - alert: FortressServiceDown
        expr: up{job="fortress"} == 0
        for: 1m
        labels:
          severity: critical
          service: fortress
        annotations:
          summary: "Fortress service is down"
          description: "Fortress service has been down for more than 1 minute"

      # High Error Rate
      - alert: FortressHighErrorRate
        expr: fortress:error_rate:5m > 0.05
        for: 5m
        labels:
          severity: warning
          service: fortress
        annotations:
          summary: "Fortress high error rate"
          description: "Fortress error rate is {{ $value | humanizePercentage }} for the last 5 minutes"

      # High Response Time
      - alert: FortressHighResponseTime
        expr: fortress:response_time_p95:5m > 1
        for: 5m
        labels:
          severity: warning
          service: fortress
        annotations:
          summary: "Fortress high response time"
          description: "Fortress 95th percentile response time is {{ $value }}s for the last 5 minutes"

      # Database Connection Exhaustion
      - alert: FortressDBConnectionExhaustion
        expr: fortress:db_connection_utilization > 0.9
        for: 2m
        labels:
          severity: critical
          service: fortress
        annotations:
          summary: "Fortress database connection exhaustion"
          description: "Fortress database connection utilization is {{ $value | humanizePercentage }}"

      # Low Cache Hit Rate
      - alert: FortressLowCacheHitRate
        expr: fortress:cache_hit_rate:5m < 0.8
        for: 10m
        labels:
          severity: warning
          service: fortress
        annotations:
          summary: "Fortress low cache hit rate"
          description: "Fortress cache hit rate is {{ $value | humanizePercentage }} for the last 10 minutes"

      # High Memory Usage
      - alert: FortressHighMemoryUsage
        expr: fortress_memory_usage_bytes / (1024*1024*1024) > 4
        for: 5m
        labels:
          severity: warning
          service: fortress
        annotations:
          summary: "Fortress high memory usage"
          description: "Fortress memory usage is {{ $value }}GB"

      # High CPU Usage
      - alert: FortressHighCPUUsage
        expr: fortress_cpu_usage_percent > 80
        for: 5m
        labels:
          severity: warning
          service: fortress
        annotations:
          summary: "Fortress high CPU usage"
          description: "Fortress CPU usage is {{ $value }}%"

      # Disk Space Low
      - alert: FortressDiskSpaceLow
        expr: fortress_disk_usage_bytes / fortress_disk_capacity_bytes > 0.85
        for: 10m
        labels:
          severity: critical
          service: fortress
        annotations:
          summary: "Fortress disk space low"
          description: "Fortress disk usage is {{ $value | humanizePercentage }}"

      # Authentication Failures
      - alert: FortressAuthenticationFailures
        expr: rate(fortress_authentication_total{result="failure"}[5m]) > 10
        for: 2m
        labels:
          severity: warning
          service: fortress
        annotations:
          summary: "Fortress authentication failures"
          description: "Fortress is experiencing {{ $value }} authentication failures per second"

      # Storage Growth Anomaly
      - alert: FortressStorageGrowthAnomaly
        expr: fortress:storage_growth_rate:1h > 1073741824  # 1GB/hour
        for: 30m
        labels:
          severity: warning
          service: fortress
        annotations:
          summary: "Fortress storage growth anomaly"
          description: "Fortress storage is growing at {{ $value | humanizeBytes }}/hour"

      # Key Rotation Failure
      - alert: FortressKeyRotationFailure
        expr: increase(fortress_key_rotation_events_total{result="failure"}[1h]) > 0
        for: 0m
        labels:
          severity: critical
          service: fortress
        annotations:
          summary: "Fortress key rotation failure"
          description: "Fortress key rotation has failed"
```

## Dashboard Setup

### Grafana Dashboards

#### Main Fortress Dashboard
```json
{
  "dashboard": {
    "id": null,
    "title": "Fortress Overview",
    "tags": ["fortress"],
    "timezone": "browser",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(fortress_requests_total[5m])",
            "legendFormat": "{{method}} {{status}}"
          }
        ],
        "yAxes": [
          {
            "label": "Requests/sec"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.50, rate(fortress_request_duration_seconds_bucket[5m]))",
            "legendFormat": "50th percentile"
          },
          {
            "expr": "histogram_quantile(0.95, rate(fortress_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          },
          {
            "expr": "histogram_quantile(0.99, rate(fortress_request_duration_seconds_bucket[5m]))",
            "legendFormat": "99th percentile"
          }
        ],
        "yAxes": [
          {
            "label": "Seconds"
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
        ],
        "valueMaps": [
          {
            "value": null,
            "text": "N/A"
          }
        ],
        "thresholds": "0.01,0.05"
      },
      {
        "title": "Active Connections",
        "type": "singlestat",
        "targets": [
          {
            "expr": "fortress_active_connections",
            "legendFormat": "Active Connections"
          }
        ]
      },
      {
        "title": "Database Connections",
        "type": "graph",
        "targets": [
          {
            "expr": "fortress_database_connections_active",
            "legendFormat": "Active"
          },
          {
            "expr": "fortress_database_connections_idle",
            "legendFormat": "Idle"
          }
        ]
      },
      {
        "title": "Cache Performance",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(fortress_cache_hits_total[5m])",
            "legendFormat": "Cache Hits/sec"
          },
          {
            "expr": "rate(fortress_cache_misses_total[5m])",
            "legendFormat": "Cache Misses/sec"
          }
        ]
      },
      {
        "title": "Cache Hit Rate",
        "type": "singlestat",
        "targets": [
          {
            "expr": "rate(fortress_cache_hits_total[5m]) / (rate(fortress_cache_hits_total[5m]) + rate(fortress_cache_misses_total[5m]))",
            "legendFormat": "Hit Rate"
          }
        ],
        "unit": "percent",
        "thresholds": "0.8,0.9"
      },
      {
        "title": "Memory Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "fortress_memory_usage_bytes / 1024 / 1024 / 1024",
            "legendFormat": "Memory (GB)"
          }
        ]
      },
      {
        "title": "CPU Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "fortress_cpu_usage_percent",
            "legendFormat": "CPU %"
          }
        ]
      },
      {
        "title": "Storage Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "fortress_storage_bytes_total / 1024 / 1024 / 1024",
            "legendFormat": "{{database}} Storage (GB)"
          }
        ]
      },
      {
        "title": "Authentication Events",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(fortress_authentication_total[5m])",
            "legendFormat": "{{result}} Auth/sec"
          }
        ]
      },
      {
        "title": "Encryption Operations",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(fortress_encryption_operations_total[5m])",
            "legendFormat": "{{operation}} {{algorithm}}/sec"
          }
        ]
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "30s"
  }
}
```

#### Security Dashboard
```json
{
  "dashboard": {
    "id": null,
    "title": "Fortress Security",
    "tags": ["fortress", "security"],
    "timezone": "browser",
    "panels": [
      {
        "title": "Authentication Success Rate",
        "type": "singlestat",
        "targets": [
          {
            "expr": "rate(fortress_authentication_total{result=\"success\"}[5m]) / rate(fortress_authentication_total[5m])",
            "legendFormat": "Success Rate"
          }
        ],
        "unit": "percent",
        "thresholds": "0.95,0.99"
      },
      {
        "title": "Authentication Failures",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(fortress_authentication_total{result=\"failure\"}[5m])",
            "legendFormat": "Failures/sec"
          }
        ]
      },
      {
        "title": "Authorization Events",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(fortress_authorization_total[5m])",
            "legendFormat": "{{result}} Authz/sec"
          }
        ]
      },
      {
        "title": "Key Rotation Events",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(fortress_key_rotation_events_total[5m])",
            "legendFormat": "{{result}} Rotations/sec"
          }
        ]
      },
      {
        "title": "Encryption Operations by Algorithm",
        "type": "piechart",
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

## Log Management

### Log Configuration

#### Fortress Logging Setup
```toml
[logging]
level = "info"
format = "json"
file = "/var/log/fortress/fortress.log"
max_size = "100MB"
max_files = 10
rotate = true

[logging.fields]
service = "fortress"
environment = "production"
version = "0.1.0"

[logging.outputs]
console = true
file = true
syslog = false
```

#### Log Structure
```json
{
  "timestamp": "2025-03-24T10:30:00.123Z",
  "level": "info",
  "message": "Request completed",
  "service": "fortress",
  "request_id": "req_123456789",
  "method": "POST",
  "path": "/api/v1/databases",
  "status": 201,
  "duration_ms": 45,
  "user_id": "user_123",
  "database": "myapp_db",
  "ip_address": "192.168.1.100",
  "user_agent": "Fortress-CLI/0.1.0"
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

<filter fortress>
  @type record_transformer
  <record>
    hostname ${hostname}
    environment production
  </record>
</filter>

<match fortress>
  @type elasticsearch
  host elasticsearch
  port 9200
  index_name fortress
  type_name _doc
  include_tag_key true
  tag_key @log_name
  <buffer>
    @type file
    path /var/log/fluentd/buffer
    flush_mode interval
    retry_type exponential_backoff
    flush_thread_count 2
    flush_interval 5s
    retry_forever
    retry_max_interval 30
    chunk_limit_size 2M
    queue_limit_length 8
    overflow_action block
  </buffer>
</match>
```

#### Loki Configuration
```yaml
# loki-config.yaml
auth_enabled: false

server:
  http_listen_port: 3100

ingester:
  lifecycler:
    address: 127.0.0.1
    ring:
      kvstore:
        store: inmemory
      replication_factor: 1
    final_sleep: 0s
  chunk_idle_period: 1h
  max_chunk_age: 1h
  chunk_target_size: 1048576
  chunk_retain_period: 30s

schema_config:
  configs:
    - from: 2020-10-24
      store: boltdb-shipper
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 24h

storage_config:
  boltdb_shipper:
    active_index_directory: /loki/boltdb-shipper-active
    cache_location: /loki/boltdb-shipper-cache
    shared_store: filesystem
  filesystem:
    directory: /loki/chunks

limits_config:
  enforce_metric_name: false
  reject_old_samples: true
  reject_old_samples_max_age: 168h

chunk_store_config:
  max_look_back_period: 0s

table_manager:
  retention_deletes_enabled: false
  retention_period: 0s
```

## Distributed Tracing

### Jaeger Setup

#### Jaeger Configuration
```yaml
# jaeger-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jaeger
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: jaeger
  template:
    metadata:
      labels:
        app: jaeger
    spec:
      containers:
      - name: jaeger
        image: jaegertracing/all-in-one:latest
        ports:
        - containerPort: 16686
          name: ui
        - containerPort: 14268
          name: collector
        env:
        - name: COLLECTOR_ZIPKIN_HTTP_PORT
          value: "9411"
```

#### Fortress Tracing Configuration
```toml
[tracing]
enabled = true
service_name = "fortress"
jaeger_endpoint = "http://jaeger:14268/api/traces"
sampling_rate = 0.1

[tracing.tags]
environment = "production"
version = "0.1.0"
```

## Performance Monitoring

### Application Performance Monitoring (APM)

#### APM Configuration
```toml
[apm]
enabled = true
service_name = "fortress"
environment = "production"
sample_rate = 0.1

[apm.endpoints]
metrics = "http://apm-server:8200"
traces = "http://apm-server:8200"
```

#### Custom Metrics
```toml
[custom_metrics]
business_metrics_enabled = true
performance_metrics_enabled = true
security_metrics_enabled = true

[custom_metrics.business]
database_operations = true
user_sessions = true
api_usage = true

[custom_metrics.performance]
query_performance = true
encryption_performance = true
storage_performance = true

[custom_metrics.security]
authentication_events = true
authorization_events = true
key_rotation_events = true
```

## Alerting Best Practices

### Alert Hierarchy
1. **Critical**: Service down, data loss, security breach
2. **Warning**: Performance degradation, resource exhaustion
3. **Info**: Scheduled maintenance, version updates

### Alert Design Principles
- **Actionable**: Each alert should have clear action steps
- **Specific**: Clear indication of what's wrong
- **Timely**: Alert at the right time (not too early/late)
- **Contextual**: Include relevant context for troubleshooting

### Alert Fatigue Prevention
```yaml
# Group alerts to reduce noise
group_by: ['alertname', 'cluster', 'service']
group_wait: 10s
group_interval: 10s
repeat_interval: 1h

# Use inhibition rules to suppress noise
inhibit_rules:
  - source_match:
      alertname: 'FortressServiceDown'
    target_match:
      severity: 'warning'
    equal: ['service']
```

## Monitoring as Code

### Terraform Configuration

#### Prometheus Terraform
```hcl
resource "prometheus_rule_group" "fortress" {
  name = "fortress.rules"
  interval = "30s"
  rules {
    record = "fortress:request_rate:5m"
    expr   = "rate(fortress_requests_total[5m])"
  }
  
  rules {
    alert = "FortressServiceDown"
    expr   = "up{job=\"fortress\"} == 0"
    for    = "1m"
    labels = {
      severity = "critical"
      service  = "fortress"
    }
    annotations = {
      summary = "Fortress service is down"
      description = "Fortress service has been down for more than 1 minute"
    }
  }
}
```

#### Grafana Dashboard Terraform
```hcl
resource "grafana_dashboard" "fortress" {
  config_json = file("${path.module}/dashboards/fortress-overview.json")
  
  folder = "Fortress"
  message = "Fortress monitoring dashboard"
}
```

## Troubleshooting Monitoring

### Common Issues

#### Metrics Not Appearing
```bash
# Check Fortress metrics endpoint
curl http://fortress:9090/metrics

# Check Prometheus configuration
promtool check config prometheus.yml

# Check Prometheus targets
curl http://prometheus:9090/api/v1/targets
```

#### Alerts Not Firing
```bash
# Check AlertManager configuration
amtool config routes test alertname=FortressServiceDown

# Check alert rules
promtool check rules alert_rules.yml

# Check AlertManager status
curl http://alertmanager:9093/api/v1/status
```

#### Dashboard Issues
```bash
# Check Grafana data source
curl -u admin:password http://grafana:3000/api/datasources

# Check dashboard JSON
jq . dashboards/fortress-overview.json
```

---

**Last Updated**: 2025-03-24  
**Version**: v0.1.0  
**Status**: Alpha - Features Under Development
