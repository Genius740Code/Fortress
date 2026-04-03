# Third-Party Integrations Guide

Comprehensive guide for integrating Fortress with popular third-party services and platforms.

## Table of Contents

- [Cloud Provider Integrations](#cloud-provider-integrations)
- [Database Integrations](#database-integrations)
- [Monitoring & Observability](#monitoring--observability)
- [Identity & Access Management](#identity--access-management)
- [CI/CD Pipeline Integrations](#cicd-pipeline-integrations)
- [Security Tools Integration](#security-tools-integration)
- [API Gateway & Service Mesh](#api-gateway--service-mesh)
- [Backup & Disaster Recovery](#backup--disaster-recovery)

---

## Cloud Provider Integrations

### AWS Integration

#### AWS S3 Storage Backend

```yaml
# config/aws-s3.yaml
storage:
  backend: "s3"
  s3:
    region: "us-west-2"
    bucket: "fortress-encrypted-data"
    access_key_id: "${AWS_ACCESS_KEY_ID}"
    secret_access_key: "${AWS_SECRET_ACCESS_KEY}"
    encryption:
      enabled: true
      algorithm: "aes256"
      server_side_encryption: "aws:kms"
      kms_key_id: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
```

```rust
use fortress_core::storage::{S3Storage, StorageConfig};

// Configure S3 storage with Fortress encryption
let s3_config = StorageConfig::builder()
    .bucket("fortress-encrypted-data")
    .region("us-west-2")
    .prefix("secure-data/")
    .encryption_enabled(true)
    .build();

let s3_storage = S3Storage::new(s3_config).await?;

// Store encrypted data in S3
let encrypted_data = fortress.encrypt_data(sensitive_data).await?;
s3_storage.put("customer-records/2024/record-001.json", encrypted_data).await?;
```

#### AWS KMS Integration

```rust
use fortress_core::kms::{AWSKMS, KMSConfig};

// Configure AWS KMS for key management
let kms_config = KMSConfig::builder()
    .region("us-west-2")
    .key_id("arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012")
    .build();

let aws_kms = AWSKMS::new(kms_config).await?;

// Use KMS for key operations
let data_key = aws_kms.generate_data_key(32).await?;
let encrypted_data = aws_kms.encrypt(plaintext, &data_key).await?;
```

#### AWS Lambda Integration

```python
# lambda_function.py
import json
import fortress
from fortress import FortressClient

# Initialize Fortress client in Lambda
def lambda_handler(event, context):
    fortress_client = FortressClient(
        server_url="https://fortress.example.com",
        api_key=os.environ['FORTRESS_API_KEY']
    )
    
    # Process incoming data with encryption
    for record in event['Records']:
        payload = json.loads(record['body'])
        
        # Encrypt sensitive fields
        encrypted_payload = fortress_client.encrypt_fields(payload, [
            'ssn', 'credit_card', 'email'
        ])
        
        # Store encrypted data
        fortress_client.store('processed_data', encrypted_payload)
    
    return {
        'statusCode': 200,
        'body': json.dumps({'processed': len(event['Records'])})
    }
```

### Azure Integration

#### Azure Blob Storage

```yaml
# config/azure-blob.yaml
storage:
  backend: "azure_blob"
  azure:
    storage_account: "fortressstorage"
    container: "encrypted-data"
    access_key: "${AZURE_STORAGE_ACCESS_KEY}"
    encryption:
      enabled: true
      algorithm: "aes256-gcm"
      customer_managed_key: true
      key_vault_url: "https://fortress-kv.vault.azure.net/"
```

```rust
use fortress_core::storage::{AzureBlobStorage, AzureConfig};

// Configure Azure Blob Storage
let azure_config = AzureConfig::builder()
    .storage_account("fortressstorage")
    .container("encrypted-data")
    .access_key(&std::env::var("AZURE_STORAGE_ACCESS_KEY")?)
    .encryption_enabled(true)
    .build();

let azure_storage = AzureBlobStorage::new(azure_config).await?;

// Store encrypted data in Azure Blob
let encrypted_data = fortress.encrypt_data(sensitive_data).await?;
azure_storage.put_blob("documents/secure-doc-001.pdf", encrypted_data).await?;
```

#### Azure Key Vault Integration

```rust
use fortress_core::keyvault::{AzureKeyVault, KeyVaultConfig};

// Configure Azure Key Vault
let kv_config = KeyVaultConfig::builder()
    .vault_url("https://fortress-kv.vault.azure.net/")
    .tenant_id(&std::env::var("AZURE_TENANT_ID")?)
    .client_id(&std::env::var("AZURE_CLIENT_ID")?)
    .client_secret(&std::env::var("AZURE_CLIENT_SECRET")?)
    .build();

let key_vault = AzureKeyVault::new(kv_config).await?;

// Use Key Vault for encryption
let encryption_key = key_vault.get_key("master-key").await?;
let encrypted_data = fortress.encrypt_with_key(data, &encryption_key).await?;
```

### Google Cloud Integration

#### Google Cloud Storage

```yaml
# config/gcs.yaml
storage:
  backend: "gcs"
  gcs:
    bucket: "fortress-encrypted-data"
    project_id: "fortress-project"
    credentials_file: "/path/to/service-account.json"
    encryption:
      enabled: true
      algorithm: "aes256-gcm"
      customer_managed_key: true
      key_ring: "fortress-keys"
      key_name: "master-key"
```

```rust
use fortress_core::storage::{GCSStorage, GCSConfig};

// Configure Google Cloud Storage
let gcs_config = GCSConfig::builder()
    .bucket("fortress-encrypted-data")
    .project_id("fortress-project")
    .credentials_file("/path/to/service-account.json")
    .encryption_enabled(true)
    .build();

let gcs_storage = GCSStorage::new(gcs_config).await?;

// Store encrypted data in GCS
let encrypted_data = fortress.encrypt_data(sensitive_data).await?;
gcs_storage.upload_object("secure-files/data-001.json", encrypted_data).await?;
```

---

## Database Integrations

### PostgreSQL Integration

```yaml
# config/postgresql.yaml
database:
  type: "postgresql"
  connection:
    host: "postgres.example.com"
    port: 5432
    database: "fortress_db"
    username: "fortress_user"
    password: "${POSTGRES_PASSWORD}"
    ssl_mode: "require"
    
  encryption:
    enabled: true
    algorithm: "aes256-gcm"
    field_level_encryption: true
    
    encrypted_fields:
      users: ["ssn", "email", "phone", "address"]
      orders: ["credit_card", "billing_address"]
      medical_records: ["diagnosis", "treatment", "patient_id"]
```

```rust
use fortress_core::database::{PostgreSQLAdapter, DatabaseConfig};

// Configure PostgreSQL with Fortress encryption
let db_config = DatabaseConfig::builder()
    .host("postgres.example.com")
    .port(5432)
    .database("fortress_db")
    .username("fortress_user")
    .password(&std::env::var("POSTGRES_PASSWORD")?)
    .encryption_enabled(true)
    .build();

let postgres_adapter = PostgreSQLAdapter::new(db_config).await?;

// Store encrypted data in PostgreSQL
let user_data = serde_json::json!({
    "name": "John Doe",
    "email": "john@example.com",    // Will be encrypted
    "ssn": "123-45-6789",         // Will be encrypted
    "age": 30                     // Will not be encrypted
});

postgres_adapter.insert("users", &user_data).await?;
```

### MongoDB Integration

```yaml
# config/mongodb.yaml
database:
  type: "mongodb"
  connection:
    uri: "mongodb+srv://fortress_user:${MONGODB_PASSWORD}@cluster.example.com/fortress_db"
    ssl: true
    
  encryption:
    enabled: true
    algorithm: "aes256-gcm"
    field_level_encryption: true
    
    encrypted_fields:
      customers: ["pii", "payment_info", "contact_details"]
      transactions: ["card_data", "billing_address"]
```

```javascript
// mongodb-integration.js
const { MongoClient } = require('mongodb');
const { FortressClient } = require('fortress-db');

class MongoDBFortressIntegration {
    constructor() {
        this.fortress = new FortressClient({
            serverUrl: 'https://fortress.example.com',
            apiKey: process.env.FORTRESS_API_KEY
        });
    }
    
    async connect() {
        this.client = await MongoClient.connect(process.env.MONGODB_URI);
        this.db = this.client.db('fortress_db');
    }
    
    async insertSecure(collection, document) {
        // Encrypt sensitive fields before storing
        const encryptedDoc = await this.fortress.encryptFields(document, {
            pii: ['ssn', 'email', 'phone'],
            payment: ['credit_card', 'bank_account'],
            health: ['medical_record', 'diagnosis']
        });
        
        return await this.db.collection(collection).insertOne(encryptedDoc);
    }
    
    async findSecure(collection, query) {
        const results = await this.db.collection(collection).find(query).toArray();
        
        // Decrypt sensitive fields after retrieval
        return await Promise.all(results.map(async (doc) => {
            return await this.fortress.decryptFields(doc);
        }));
    }
}

module.exports = MongoDBFortressIntegration;
```

### Redis Integration

```yaml
# config/redis.yaml
cache:
  type: "redis"
  connection:
    host: "redis.example.com"
    port: 6379
    password: "${REDIS_PASSWORD}"
    ssl: true
    database: 0
    
  encryption:
    enabled: true
    algorithm: "aes256-gcm"
    encrypt_keys: true
    
  clustering:
    enabled: true
    nodes:
      - "redis-01.example.com:6379"
      - "redis-02.example.com:6379"
      - "redis-03.example.com:6379"
```

```python
# redis-integration.py
import redis
import json
from fortress import FortressClient

class RedisFortressIntegration:
    def __init__(self):
        self.fortress = FortressClient(
            server_url="https://fortress.example.com",
            api_key=os.environ['FORTRESS_API_KEY']
        )
        self.redis_client = redis.Redis(
            host='redis.example.com',
            port=6379,
            password=os.environ['REDIS_PASSWORD'],
            ssl=True,
            decode_responses=False
        )
    
    async def set_secure(self, key, value, ttl=3600):
        """Store encrypted value in Redis"""
        encrypted_value = await self.fortress.encrypt(value)
        encrypted_key = await self.fortress.encrypt(key)
        
        return self.redis_client.setex(
            encrypted_key, 
            ttl, 
            encrypted_value
        )
    
    async def get_secure(self, key):
        """Retrieve and decrypt value from Redis"""
        encrypted_key = await self.fortress.encrypt(key)
        encrypted_value = self.redis_client.get(encrypted_key)
        
        if encrypted_value:
            return await self.fortress.decrypt(encrypted_value)
        return None
```

---

## Monitoring & Observability

### Prometheus Integration

```yaml
# config/prometheus.yaml
monitoring:
  prometheus:
    enabled: true
    port: 9090
    metrics_path: "/metrics"
    
    custom_metrics:
      - name: "fortress_encryption_operations_total"
        type: "counter"
        help: "Total number of encryption operations"
      
      - name: "fortress_decryption_operations_total"
        type: "counter"
        help: "Total number of decryption operations"
      
      - name: "fortress_encryption_latency_seconds"
        type: "histogram"
        help: "Encryption operation latency in seconds"
        buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
      
      - name: "fortress_active_keys"
        type: "gauge"
        help: "Number of active encryption keys"
```

```rust
use fortress_core::monitoring::{PrometheusMetrics, MetricCollector};

// Configure Prometheus metrics
let prometheus = PrometheusMetrics::builder()
    .port(9090)
    .metrics_path("/metrics")
    .add_counter("fortress_encryption_operations_total", "Total encryption operations")
    .add_histogram("fortress_encryption_latency_seconds", "Encryption latency")
    .add_gauge("fortress_active_keys", "Active keys count")
    .build();

// Track encryption operations
prometheus.increment_counter("fortress_encryption_operations_total").await?;
prometheus.record_histogram("fortress_encryption_latency_seconds", 0.045).await?;
prometheus.set_gauge("fortress_active_keys", 42).await?;
```

### Grafana Dashboard Integration

```json
{
  "dashboard": {
    "title": "Fortress Security Metrics",
    "panels": [
      {
        "title": "Encryption Operations Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(fortress_encryption_operations_total[5m])",
            "legendFormat": "Encryption Ops/sec"
          },
          {
            "expr": "rate(fortress_decryption_operations_total[5m])",
            "legendFormat": "Decryption Ops/sec"
          }
        ]
      },
      {
        "title": "Encryption Latency",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(fortress_encryption_latency_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          },
          {
            "expr": "histogram_quantile(0.50, rate(fortress_encryption_latency_seconds_bucket[5m]))",
            "legendFormat": "50th percentile"
          }
        ]
      },
      {
        "title": "Active Keys",
        "type": "singlestat",
        "targets": [
          {
            "expr": "fortress_active_keys",
            "legendFormat": "Active Keys"
          }
        ]
      }
    ]
  }
}
```

### Datadog Integration

```python
# datadog-integration.py
from datadog import initialize, statsd
from fortress import FortressClient
import time

class DatadogFortressMonitor:
    def __init__(self):
        initialize(
            api_key=os.environ['DATADOG_API_KEY'],
            app_key=os.environ['DATADOG_APP_KEY']
        )
        self.fortress = FortressClient(
            server_url="https://fortress.example.com",
            api_key=os.environ['FORTRESS_API_KEY']
        )
    
    async def monitor_encryption(self, data):
        """Monitor encryption operation with Datadog"""
        start_time = time.time()
        
        # Perform encryption
        encrypted_data = await self.fortress.encrypt(data)
        
        # Record metrics
        duration = time.time() - start_time
        statsd.histogram('fortress.encryption.duration', duration)
        statsd.increment('fortress.encryption.count')
        
        # Check for performance issues
        if duration > 0.1:  # 100ms threshold
            statsd.event(
                'Fortress Slow Encryption',
                f'Encryption took {duration:.3f}s',
                alert_type='warning'
            )
        
        return encrypted_data
    
    def track_key_rotation(self, key_id, status):
        """Track key rotation events"""
        statsd.increment('fortress.key_rotation.count', tags=[f'status:{status}'])
        statsd.event(
            'Fortress Key Rotation',
            f'Key {key_id} rotation {status}',
            tags=['key_rotation']
        )
```

---

## Identity & Access Management

### Okta Integration

```yaml
# config/okta.yaml
authentication:
  provider: "okta"
  okta:
    domain: "your-org.okta.com"
    client_id: "${OKTA_CLIENT_ID}"
    client_secret: "${OKTA_CLIENT_SECRET}"
    redirect_uri: "https://fortress.example.com/auth/callback"
    
    mfa:
      required: true
      methods: ["push", "sms", "totp"]
    
    groups:
      mapping:
        "FortressAdmins": "admin"
        "FortressUsers": "user"
        "FortressReadOnly": "readonly"
```

```rust
use fortress_core::auth::{OktaProvider, AuthConfig};

// Configure Okta authentication
let okta_config = AuthConfig::builder()
    .domain("your-org.okta.com")
    .client_id(&std::env::var("OKTA_CLIENT_ID")?)
    .client_secret(&std::env::var("OKTA_CLIENT_SECRET")?)
    .redirect_uri("https://fortress.example.com/auth/callback")
    .mfa_required(true)
    .build();

let okta_provider = OktaProvider::new(okta_config).await?;

// Authenticate user with Okta
let auth_result = okta_provider.authenticate(username, password).await?;
if auth_result.success {
    let fortress_token = fortress.create_session(auth_result.user).await?;
}
```

### Azure AD Integration

```python
# azure-ad-integration.py
import msal
from fortress import FortressClient

class AzureADFortressAuth:
    def __init__(self):
        self.fortress = FortressClient(
            server_url="https://fortress.example.com",
            api_key=os.environ['FORTRESS_API_KEY']
        )
        self.app = msal.ConfidentialClientApplication(
            client_id=os.environ['AZURE_CLIENT_ID'],
            client_credential=os.environ['AZURE_CLIENT_SECRET'],
            authority=f"https://login.microsoftonline.com/{os.environ['AZURE_TENANT_ID']}"
        )
    
    async def authenticate_with_azure(self, token):
        """Authenticate using Azure AD token"""
        # Validate Azure AD token
        result = self.app.acquire_token_by_authorization_code(
            token,
            scopes=["https://fortress.example.com/.default"]
        )
        
        if "access_token" in result:
            # Create Fortress session
            user_info = self.extract_user_info(result["id_token_claims"])
            fortress_session = await self.fortress.create_session(user_info)
            return fortress_session
        
        raise Exception("Azure AD authentication failed")
    
    def extract_user_info(self, claims):
        """Extract user information from Azure AD claims"""
        return {
            "id": claims.get("oid"),
            "email": claims.get("email"),
            "name": claims.get("name"),
            "groups": claims.get("groups", []),
            "roles": claims.get("roles", [])
        }
```

---

## CI/CD Pipeline Integrations

### GitHub Actions Integration

```yaml
# .github/workflows/fortress-security.yml
name: Fortress Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Fortress CLI
      run: |
        curl -L "https://github.com/fortress-security/fortress/releases/latest/download/fortress-linux-amd64-latest" -o fortress
        chmod +x fortress
        sudo mv fortress /usr/local/bin/
    
    - name: Configure Fortress
      run: |
        fortress config set server.url "https://fortress.example.com"
        fortress config set auth.token "${{ secrets.FORTRESS_TOKEN }}"
    
    - name: Scan for Secrets
      run: |
        fortress scan secrets --path . --format json --output security-report.json
    
    - name: Encrypt Sensitive Files
      run: |
        fortress encrypt --input config/secrets.yaml --output config/secrets.yaml.enc
        fortress encrypt --input .env --output .env.enc
    
    - name: Upload Security Report
      uses: actions/upload-artifact@v3
      with:
        name: security-report
        path: security-report.json
    
    - name: Check for Vulnerabilities
      run: |
        fortress scan vulnerabilities --path . --fail-on-high
```

### Jenkins Pipeline Integration

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        FORTRESS_SERVER = 'https://fortress.example.com'
        FORTRESS_TOKEN = credentials('fortress-token')
    }
    
    stages {
        stage('Setup Fortress') {
            steps {
                sh '''
                    curl -L "https://github.com/fortress-security/fortress/releases/latest/download/fortress-linux-amd64-latest" -o fortress
                    chmod +x fortress
                    sudo mv fortress /usr/local/bin/
                    fortress config set server.url ${FORTRESS_SERVER}
                    fortress config set auth.token ${FORTRESS_TOKEN}
                '''
            }
        }
        
        stage('Security Scan') {
            steps {
                sh 'fortress scan secrets --path . --format junit --output security-scan.xml'
                sh 'fortress scan vulnerabilities --path . --fail-on-high'
                
                publishTestResults testResultsPattern: 'security-scan.xml'
            }
        }
        
        stage('Encrypt Artifacts') {
            steps {
                sh '''
                    fortress encrypt --input target/application.jar --output target/application.jar.enc
                    fortress encrypt --input config/production.yml --output config/production.yml.enc
                '''
                
                archiveArtifacts artifacts: 'target/*.jar.enc, config/*.yml.enc', fingerprint: true
            }
        }
        
        stage('Deploy') {
            steps {
                sh '''
                    fortress deploy \
                        --artifact target/application.jar.enc \
                        --config config/production.yml.enc \
                        --environment production
                '''
            }
        }
    }
    
    post {
        always {
            sh 'fortress audit log --pipeline ${env.JOB_NAME} --build ${env.BUILD_NUMBER}'
        }
    }
}
```

---

## Security Tools Integration

### OWASP ZAP Integration

```python
# owasp-zap-integration.py
import requests
from fortress import FortressClient

class ZAPFortressIntegration:
    def __init__(self):
        self.fortress = FortressClient(
            server_url="https://fortress.example.com",
            api_key=os.environ['FORTRESS_API_KEY']
        )
        self.zap_api = "http://localhost:8080"
        self.zap_key = os.environ['ZAP_API_KEY']
    
    async def scan_and_encrypt_findings(self, target_url):
        """Scan with ZAP and encrypt sensitive findings"""
        # Start ZAP scan
        scan_id = self.start_zap_scan(target_url)
        
        # Wait for scan completion
        self.wait_for_scan(scan_id)
        
        # Get scan results
        findings = self.get_zap_results(scan_id)
        
        # Encrypt sensitive findings before storage
        encrypted_findings = []
        for finding in findings:
            if self.is_sensitive(finding):
                encrypted_finding = await self.fortress.encrypt_field(
                    finding, 
                    ['evidence', 'attack', 'param']
                )
                encrypted_findings.append(encrypted_finding)
            else:
                encrypted_findings.append(finding)
        
        # Store encrypted findings
        await self.fortress.store('security_scan_results', {
            'scan_id': scan_id,
            'target': target_url,
            'findings': encrypted_findings,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        return encrypted_findings
    
    def is_sensitive(self, finding):
        """Determine if finding contains sensitive data"""
        sensitive_keywords = ['password', 'token', 'key', 'secret', 'credential']
        finding_text = str(finding).lower()
        return any(keyword in finding_text for keyword in sensitive_keywords)
```

### Splunk Integration

```yaml
# config/splunk.yaml
logging:
  splunk:
    enabled: true
    hec_url: "https://splunk.example.com:8088/services/collector/event"
    hec_token: "${SPLUNK_HEC_TOKEN}"
    index: "fortress_security"
    source: "fortress"
    sourcetype: "json"
    
    event_types:
      - "encryption_operations"
      - "key_rotation_events"
      - "authentication_events"
      - "access_denials"
      - "security_violations"
```

```rust
use fortress_core::logging::{SplunkLogger, LogConfig};

// Configure Splunk logging
let splunk_config = LogConfig::builder()
    .hec_url("https://splunk.example.com:8088/services/collector/event")
    .hec_token(&std::env::var("SPLUNK_HEC_TOKEN")?)
    .index("fortress_security")
    .source("fortress")
    .sourcetype("json")
    .build();

let splunk_logger = SplunkLogger::new(splunk_config).await?;

// Log security events to Splunk
splunk_logger.log_security_event(
    "ENCRYPTION_OPERATION",
    serde_json::json!({
        "operation": "encrypt",
        "user_id": "user-123",
        "data_type": "pii",
        "algorithm": "aes256-gcm",
        "timestamp": Utc::now()
    })
).await?;
```

---

## API Gateway & Service Mesh

### Kong API Gateway Integration

```yaml
# kong-fortress-plugin.yaml
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: fortress-encryption
  namespace: kong
config:
  fortress_url: "https://fortress.example.com"
  api_key: "${FORTRESS_API_KEY}"
  encrypt_fields:
    - "ssn"
    - "credit_card"
    - "email"
    - "phone"
  decrypt_response: true
plugin: fortress-encryption
---
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: fortress-auth
  namespace: kong
config:
  fortress_url: "https://fortress.example.com"
  api_key: "${FORTRESS_API_KEY}"
  validate_tokens: true
  extract_user_info: true
plugin: fortress-authentication
```

```lua
-- kong/plugins/fortress-encryption/handler.lua
local http = require "resty.http"
local cjson = require "cjson"

local FortressEncryption = {
  PRIORITY = 1000,
  VERSION = "1.0.0"
}

function FortressEncryption:access(conf)
  -- Get request body
  local body, err = kong.request.get_body()
  if not body then
    return kong.response.exit(400, {error = "Invalid request body"})
  end
  
  -- Encrypt sensitive fields
  local httpc = http.new()
  local res, err = httpc:request_uri(conf.fortress_url .. "/api/v1/encrypt-fields", {
    method = "POST",
    body = cjson.encode({
      data = body,
      fields = conf.encrypt_fields
    }),
    headers = {
      ["Content-Type"] = "application/json",
      ["Authorization"] = "Bearer " .. conf.api_key
    }
  })
  
  if not res then
    return kong.response.exit(500, {error = "Encryption service unavailable"})
  end
  
  local encrypted_data = cjson.decode(res.body)
  kong.service.request.set_body(encrypted_data.data)
end

return FortressEncryption
```

### Istio Service Mesh Integration

```yaml
# istio-fortress-mesh.yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: fortress-default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
---
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: fortress-service
  namespace: default
spec:
  hosts:
  - fortress.example.com
  http:
  - match:
    - uri:
        prefix: "/api/v1/encrypt"
    route:
    - destination:
        host: fortress
        port:
          number: 8080
    fault:
      delay:
        percentage:
          value: 0.1
        fixedDelay: 5s
---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: fortress-destination
  namespace: default
spec:
  host: fortress
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
    connectionPool:
      tcp:
        maxConnections: 100
      http:
        http1MaxPendingRequests: 50
        maxRequestsPerConnection: 10
    loadBalancer:
      simple: LEAST_CONN
```

---

## Backup & Disaster Recovery

### Veeam Integration

```python
# veeam-fortress-integration.py
import requests
from fortress import FortressClient

class VeeamFortressBackup:
    def __init__(self):
        self.fortress = FortressClient(
            server_url="https://fortress.example.com",
            api_key=os.environ['FORTRESS_API_KEY']
        )
        self.veeam_api = "https://veeam.example.com:9419"
        self.veeam_token = self.get_veeam_token()
    
    async def create_encrypted_backup(self, job_name):
        """Create encrypted backup using Veeam"""
        # Start Veeam backup job
        backup_job = self.start_veeam_backup(job_name)
        
        # Monitor backup progress
        while not self.is_backup_complete(backup_job.id):
            await asyncio.sleep(30)
        
        # Get backup file path
        backup_file = self.get_backup_file(backup_job.id)
        
        # Encrypt backup file with Fortress
        with open(backup_file, 'rb') as f:
            backup_data = f.read()
        
        encrypted_backup = await self.fortress.encrypt(backup_data)
        
        # Store encrypted backup
        encrypted_filename = backup_file + ".enc"
        with open(encrypted_filename, 'wb') as f:
            f.write(encrypted_backup)
        
        # Store metadata in Fortress
        await self.fortress.store('backup_metadata', {
            'job_name': job_name,
            'backup_id': backup_job.id,
            'encrypted_file': encrypted_filename,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        return encrypted_filename
    
    async def restore_encrypted_backup(self, encrypted_file, target_location):
        """Restore encrypted backup"""
        # Decrypt backup file
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_backup = await self.fortress.decrypt(encrypted_data)
        
        # Restore with Veeam
        temp_file = encrypted_file.replace('.enc', '.temp')
        with open(temp_file, 'wb') as f:
            f.write(decrypted_backup)
        
        restore_job = self.start_veeam_restore(temp_file, target_location)
        
        # Clean up temp file
        os.remove(temp_file)
        
        return restore_job
```

---

## Best Practices

### Security Best Practices

1. **Always use TLS** for all external integrations
2. **Validate all inputs** before processing
3. **Implement proper error handling** to avoid information leakage
4. **Use short-lived tokens** for authentication
5. **Monitor integration health** and performance

### Performance Best Practices

1. **Batch operations** when possible
2. **Use connection pooling** for database integrations
3. **Implement caching** for frequently accessed data
4. **Optimize network calls** with proper timeout handling
5. **Monitor latency** and optimize bottlenecks

### Reliability Best Practices

1. **Implement retry logic** with exponential backoff
2. **Use circuit breakers** for external service calls
3. **Implement health checks** for all integrations
4. **Plan for failover** scenarios
5. **Test disaster recovery** procedures regularly

---

## Troubleshooting

### Common Integration Issues

1. **Authentication Failures**
   - Check API keys and tokens
   - Verify permissions and scopes
   - Ensure proper time synchronization

2. **Network Connectivity**
   - Verify firewall rules
   - Check DNS resolution
   - Test TLS certificates

3. **Performance Issues**
   - Monitor latency metrics
   - Check resource utilization
   - Optimize batch sizes

4. **Data Corruption**
   - Verify encryption/decryption processes
   - Check data integrity
   - Validate backup/restore procedures

### Debug Tools

```bash
# Test Fortress connectivity
fortress ping --server https://fortress.example.com

# Check authentication
fortress auth test --token YOUR_TOKEN

# Validate encryption
fortress encrypt --test --algorithm aes256-gcm

# Monitor integration health
fortress monitor --integration aws --verbose
```

---

## Conclusion

This guide provides comprehensive integration examples for Fortress with popular third-party services. Key takeaways:

1. **Flexible Integration**: Fortress integrates seamlessly with major cloud providers and services
2. **Security First**: All integrations maintain Fortress security guarantees
3. **Performance Optimized**: Integration patterns designed for production workloads
4. **Monitoring Ready**: Built-in observability for all integrations

For additional help:
- [API Reference](API_REFERENCE.md)
- [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md)
- [Community Support](https://github.com/Genius740Code/Fortress/discussions)

---

**Last Updated**: 2025-03-24  
**Version**: 1.0.0  
**Maintainer**: Fortress Development Team
