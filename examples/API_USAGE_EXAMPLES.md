# Fortress API Usage Examples

This repository contains practical examples of using the Fortress REST API with various programming languages and use cases.

## Quick Start

1. Start the Fortress server:
```bash
cargo run --bin fortress-server
```

2. The server will be available at `http://localhost:8080`

## Examples

### 1. Basic Data Storage and Retrieval

#### Python
```python
import requests
import json
import time

BASE_URL = "http://localhost:8080"

class FortressClient:
    def __init__(self, base_url=BASE_URL):
        self.base_url = base_url
        self.session = requests.Session()
        self.token = None
    
    def login(self, username, password):
        """Authenticate and get JWT token"""
        response = self.session.post(
            f"{self.base_url}/api/v1/auth/login",
            json={"username": username, "password": password}
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                self.token = data["data"]["access_token"]
                self.session.headers.update({
                    "Authorization": f"Bearer {self.token}"
                })
                return True
        return False
    
    def store_data(self, data, metadata=None):
        """Store encrypted data"""
        if not self.token:
            raise Exception("Not authenticated - call login() first")
            
        payload = {
            "data": data,
            "metadata": metadata or {}
        }
        
        response = self.session.post(
            f"{self.base_url}/api/v1/data",
            json=payload
        )
        return response.json()
    
    def retrieve_data(self, data_id):
        """Retrieve and decrypt data"""
        if not self.token:
            raise Exception("Not authenticated - call login() first")
            
        response = self.session.get(f"{self.base_url}/api/v1/data/{data_id}")
        return response.json()
    
    def delete_data(self, data_id):
        """Delete data"""
        if not self.token:
            raise Exception("Not authenticated - call login() first")
            
        response = self.session.delete(f"{self.base_url}/api/v1/data/{data_id}")
        return response.json()
    
    def list_data(self):
        """List all stored data"""
        if not self.token:
            raise Exception("Not authenticated - call login() first")
            
        response = self.session.get(f"{self.base_url}/api/v1/data")
        return response.json()

# Usage example
def main():
    client = FortressClient()
    
    # Authenticate first
    print("Authenticating...")
    if not client.login("admin", "your-secure-password"):
        print("Authentication failed")
        return
    
    print("✅ Authentication successful")
    
    # Store user profile
    user_data = {
        "name": "Alice Johnson",
        "email": "alice@example.com",
        "age": 28,
        "preferences": {
            "theme": "dark",
            "notifications": True
        }
    }
    
    print("Storing user data...")
    store_result = client.store_data(
        user_data,
        metadata={"type": "user_profile", "version": "1.0"}
    )
    
    if store_result["success"]:
        data_id = store_result["data"]["id"]
        print(f"✅ Data stored with ID: {data_id}")
        
        # Retrieve the data
        print("Retrieving data...")
        retrieve_result = client.retrieve_data(data_id)
        
        if retrieve_result["success"]:
            retrieved_data = retrieve_result["data"]["data"]
            print(f"✅ Retrieved user: {retrieved_data['name']}")
            print(f"✅ Email: {retrieved_data['email']}")
        
        # List all data
        print("Listing all data...")
        list_result = client.list_data()
        if list_result["success"]:
            print(f"✅ Total items: {len(list_result['data'])}")

if __name__ == "__main__":
    main()
```

#### JavaScript/Node.js
```javascript
const axios = require('axios');

class FortressClient {
    constructor(baseUrl = 'http://localhost:8080') {
        this.baseUrl = baseUrl;
        this.client = axios.create({
            baseURL: baseUrl,
            timeout: 30000,
            headers: {
                'Content-Type': 'application/json'
            }
        });
    }

    async storeData(data, metadata = {}) {
        try {
            const response = await this.client.post('/data', {
                data,
                metadata
            });
            return response.data;
        } catch (error) {
            console.error('Store error:', error.response?.data || error.message);
            throw error;
        }
    }

    async retrieveData(dataId) {
        try {
            const response = await this.client.get(`/data/${dataId}`);
            return response.data;
        } catch (error) {
            console.error('Retrieve error:', error.response?.data || error.message);
            throw error;
        }
    }

    async deleteData(dataId) {
        try {
            const response = await this.client.delete(`/data/${dataId}`);
            return response.data;
        } catch (error) {
            console.error('Delete error:', error.response?.data || error.message);
            throw error;
        }
    }

    async listData() {
        try {
            const response = await this.client.get('/data');
            return response.data;
        } catch (error) {
            console.error('List error:', error.response?.data || error.message);
            throw error;
        }
    }
}

// Usage example
async function main() {
    const client = new FortressClient();

    try {
        // Store encrypted document
        const document = {
            title: 'Confidential Report',
            content: 'This is a secret document that will be encrypted automatically.',
            classification: 'confidential',
            author: 'John Doe',
            created: new Date().toISOString()
        };

        console.log('Storing document...');
        const storeResult = await client.storeData(
            document,
            { type: 'document', classification: 'confidential' }
        );

        if (storeResult.success) {
            const docId = storeResult.data.id;
            console.log(`Document stored with ID: ${docId}`);

            // Retrieve the document
            console.log('Retrieving document...');
            const retrieveResult = await client.retrieveData(docId);

            if (retrieveResult.success) {
                const doc = retrieveResult.data.data;
                console.log(`Retrieved: ${doc.title}`);
                console.log(`Classification: ${doc.classification}`);
                console.log(`Content length: ${doc.content.length} characters`);
            }
        }

        // List all documents
        console.log('Listing all data...');
        const listResult = await client.listData();
        if (listResult.success) {
            console.log(`Total items stored: ${listResult.data.length}`);
        }

    } catch (error) {
        console.error('Error:', error.message);
    }
}

main();
```

### 2. Field-Level Encryption

#### Python
```python
import requests
import json

BASE_URL = "http://localhost:8080"

def store_sensitive_user_data():
    """Store user data with field-level encryption for sensitive fields"""
    
    user_data = {
        "name": "Bob Smith",
        "email": "bob.smith@example.com",
        "phone": "+1-555-0123",
        "ssn": "123-45-6789",  # This will be encrypted with separate key
        "address": "123 Main St, Anytown, USA",
        "preferences": {
            "theme": "light",
            "newsletter": True
        }
    }
    
    # Configure field-level encryption for sensitive fields
    field_encryption = {
        "fields": {
            "ssn": {
                "algorithm": "aes256gcm",
                "key_id": "ssn-encryption-key",
                "sensitivity": "critical"
            },
            "phone": {
                "algorithm": "aes256gcm", 
                "key_id": "phone-encryption-key",
                "sensitivity": "high"
            }
        }
    }
    
    payload = {
        "data": user_data,
        "field_encryption": field_encryption,
        "metadata": {
            "type": "user_profile",
            "contains_pii": True,
            "field_encryption_enabled": True
        }
    }
    
    response = requests.post(f"{BASE_URL}/data", json=payload)
    result = response.json()
    
    if result["success"]:
        print("User data stored with field-level encryption")
        print(f"Data ID: {result['data']['id']}")
        
        # Show field encryption metadata
        field_metadata = result["data"]["field_metadata"]
        for field, meta in field_metadata.items():
            print(f"Field '{field}' encrypted with algorithm: {meta['algorithm']}")
    
    return result

if __name__ == "__main__":
    store_sensitive_user_data()
```

### 3. Authentication Flow

#### JavaScript
```javascript
const axios = require('axios');

class FortressAuthClient {
    constructor(baseUrl = 'http://localhost:8080') {
        this.baseUrl = baseUrl;
        this.token = null;
        this.client = axios.create({
            baseURL: baseUrl,
            timeout: 30000
        });
    }

    async login(username, password, tenantId = null) {
        try {
            const response = await this.client.post('/auth/login', {
                username,
                password,
                tenant_id: tenantId
            });
            
            if (response.data.success) {
                this.token = response.data.data.token;
                this.setupAuthenticatedClient();
                return response.data;
            }
            throw new Error('Login failed');
        } catch (error) {
            console.error('Login error:', error.response?.data || error.message);
            throw error;
        }
    }

    setupAuthenticatedClient() {
        this.client.defaults.headers.common['Authorization'] = `Bearer ${this.token}`;
    }

    async refreshToken() {
        try {
            const response = await this.client.post('/auth/refresh', {
                token: this.token
            });
            
            if (response.data.success) {
                this.token = response.data.data.token;
                this.setupAuthenticatedClient();
                return response.data;
            }
            throw new Error('Token refresh failed');
        } catch (error) {
            console.error('Refresh error:', error.response?.data || error.message);
            throw error;
        }
    }

    async storeAuthenticatedData(data) {
        if (!this.token) {
            throw new Error('Not authenticated');
        }
        
        try {
            const response = await this.client.post('/data', { data });
            return response.data;
        } catch (error) {
            if (error.response?.status === 401) {
                // Token expired, try refresh
                await this.refreshToken();
                return await this.client.post('/data', { data });
            }
            throw error;
        }
    }
}

// Usage example
async function authExample() {
    const authClient = new FortressAuthClient();

    try {
        // Login
        console.log('Logging in...');
        const loginResult = await authClient.login('alice', 'secure-password-123');
        
        if (loginResult.success) {
            console.log('Login successful!');
            console.log(`Token expires: ${loginResult.data.expires_at}`);
            
            // Store authenticated data
            const secretData = {
                message: 'This data requires authentication to access',
                user_id: loginResult.data.user.id,
                timestamp: new Date().toISOString()
            };
            
            console.log('Storing authenticated data...');
            const storeResult = await authClient.storeAuthenticatedData(secretData);
            
            if (storeResult.success) {
                console.log('Authenticated data stored successfully');
                console.log(`Data ID: ${storeResult.data.id}`);
            }
        }

    } catch (error) {
        console.error('Authentication error:', error.message);
    }
}

authExample();
```

### 4. Bulk Operations

#### Rust
```rust
use reqwest;
use serde_json::json;
use tokio;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:8080";
    
    // Generate multiple records to store
    let records: Vec<serde_json::Value> = (1..=10)
        .map(|i| {
            json!({
                "data": {
                    "id": i,
                    "name": format!("Record {}", i),
                    "value": i * 10,
                    "timestamp": chrono::Utc::now().to_rfc3339()
                },
                "metadata": {
                    "batch_id": "bulk-import-001",
                    "source": "example-script"
                }
            })
        })
        .collect();
    
    let mut stored_ids = Vec::new();
    
    // Store all records concurrently
    let mut tasks = Vec::new();
    
    for record in records {
        let client = client.clone();
        let url = format!("{}/data", base_url);
        
        let task = tokio::spawn(async move {
            match client.post(&url).json(&record).send().await {
                Ok(response) => {
                    match response.json::<serde_json::Value>() {
                        Ok(result) => {
                            if result["success"].as_bool().unwrap_or(false) {
                                Some(result["data"]["id"].as_str().unwrap().to_string())
                            } else {
                                None
                            }
                        }
                        Err(e) => {
                            eprintln!("Error parsing response: {}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error storing record: {}", e);
                    None
                }
            }
        });
        
        tasks.push(task);
    }
    
    // Wait for all tasks to complete
    let results = futures::future::join_all(tasks).await;
    
    for result in results {
        if let Ok(Some(id)) = result {
            stored_ids.push(id);
        }
    }
    
    println!("Successfully stored {} records", stored_ids.len());
    
    // Retrieve all records to verify
    let list_response = client.get(&format!("{}/data", base_url))
        .send()
        .await?;
    
    let list_result: serde_json::Value = list_response.json().await?;
    
    if list_result["success"].as_bool().unwrap_or(false) {
        let total_items = list_result["data"].as_array().unwrap().len();
        println!("Total items in database: {}", total_items);
    }
    
    Ok(())
}
```

### 5. Error Handling and Retry Logic

#### Python
```python
import requests
import time
import json
from typing import Optional, Dict, Any

class FortressClientWithRetry:
    def __init__(self, base_url: str = "http://localhost:8080", max_retries: int = 3):
        self.base_url = base_url
        self.max_retries = max_retries
        self.session = requests.Session()
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make request with retry logic"""
        url = f"{self.base_url}{endpoint}"
        
        for attempt in range(self.max_retries + 1):
            try:
                response = self.session.request(method, url, **kwargs)
                
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 429:
                    # Rate limited - wait and retry
                    retry_after = int(response.headers.get('Retry-After', 1))
                    print(f"Rate limited. Waiting {retry_after} seconds...")
                    time.sleep(retry_after)
                    continue
                elif response.status_code >= 500:
                    # Server error - retry
                    if attempt < self.max_retries:
                        wait_time = 2 ** attempt  # Exponential backoff
                        print(f"Server error. Retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                        continue
                
                # Non-retryable error
                return response.json()
                
            except requests.exceptions.RequestException as e:
                if attempt < self.max_retries:
                    wait_time = 2 ** attempt
                    print(f"Network error. Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                raise
        
        raise Exception(f"Max retries ({self.max_retries}) exceeded")
    
    def store_data(self, data: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None):
        """Store data with retry logic"""
        return self._make_request(
            'POST',
            '/data',
            json={'data': data, 'metadata': metadata or {}}
        )
    
    def retrieve_data(self, data_id: str):
        """Retrieve data with retry logic"""
        return self._make_request('GET', f'/data/{data_id}')

# Usage example
def robust_example():
    client = FortressClientWithRetry(max_retries=5)
    
    # Store data with automatic retry
    print("Storing data with retry logic...")
    try:
        result = client.store_data({
            "message": "This will be stored reliably",
            "timestamp": time.time()
        })
        
        if result["success"]:
            print("Data stored successfully!")
            data_id = result["data"]["id"]
            
            # Retrieve with retry
            print("Retrieving data...")
            retrieved = client.retrieve_data(data_id)
            
            if retrieved["success"]:
                print("Data retrieved successfully!")
                print(f"Content: {retrieved['data']['data']['message']}")
        
    except Exception as e:
        print(f"Operation failed after retries: {e}")

if __name__ == "__main__":
    robust_example()
```

### 6. Monitoring and Metrics

#### JavaScript
```javascript
const axios = require('axios');

class FortressMonitor {
    constructor(baseUrl = 'http://localhost:8080') {
        this.baseUrl = baseUrl;
        this.client = axios.create({ baseURL: baseUrl });
    }

    async getMetrics() {
        try {
            const response = await this.client.get('/metrics');
            return response.data;
        } catch (error) {
            console.error('Error fetching metrics:', error.message);
            throw error;
        }
    }

    async getPrometheusMetrics() {
        try {
            const response = await this.client.get('/metrics/prometheus');
            return response.data;
        } catch (error) {
            console.error('Error fetching Prometheus metrics:', error.message);
            throw error;
        }
    }

    async getHealthStatus() {
        try {
            const response = await this.client.get('/health');
            return response.data;
        } catch (error) {
            console.error('Error checking health:', error.message);
            throw error;
        }
    }

    async monitorServer(intervalMs = 30000) {
        console.log(`Starting server monitoring (interval: ${intervalMs}ms)`);
        
        const monitor = async () => {
            try {
                // Check health
                const health = await this.getHealthStatus();
                console.log(`Health Status: ${health.data.status}`);
                
                // Get metrics
                const metrics = await this.getMetrics();
                console.log(`Total Requests: ${metrics.metrics.requests_total}`);
                console.log(`Success Rate: ${((metrics.metrics.requests_success / metrics.metrics.requests_total) * 100).toFixed(2)}%`);
                console.log(`Avg Response Time: ${metrics.metrics.response_time_avg_ms}ms`);
                
            } catch (error) {
                console.error('Monitoring error:', error.message);
            }
        };
        
        // Initial check
        monitor();
        
        // Set up interval
        return setInterval(monitor, intervalMs);
    }
}

// Usage example
async function startMonitoring() {
    const monitor = new FortressMonitor();
    
    try {
        // Get current metrics
        console.log('Fetching current metrics...');
        const metrics = await monitor.getMetrics();
        console.log('Current Metrics:', metrics);
        
        // Get Prometheus metrics for monitoring systems
        console.log('Fetching Prometheus metrics...');
        const prometheus = await monitor.getPrometheusMetrics();
        console.log('Prometheus Metrics (first 500 chars):');
        console.log(prometheus.substring(0, 500));
        
        // Start continuous monitoring
        console.log('Starting continuous monitoring...');
        monitor.monitorServer(10000); // Monitor every 10 seconds
        
    } catch (error) {
        console.error('Monitoring setup failed:', error.message);
    }
}

startMonitoring();
```

## Running the Examples

1. **Python Examples**:
   ```bash
   cd examples/python
   pip install -r requirements.txt
   python basic_usage.py
   ```

2. **JavaScript Examples**:
   ```bash
   cd examples/javascript
   npm install
   node basic_usage.js
   ```

3. **Rust Examples**:
   ```bash
   cd examples/rust
   cargo run --example bulk_operations
   ```

## Best Practices

1. **Always handle errors gracefully** - Check the `success` field in responses
2. **Implement retry logic** - Network requests can fail temporarily
3. **Use field-level encryption** for sensitive data like SSN, credit cards
4. **Monitor rate limits** - Respect `X-RateLimit-*` headers
5. **Secure your tokens** - Store JWT tokens securely and refresh before expiry
6. **Validate input** - Ensure data is properly formatted before sending
7. **Use appropriate algorithms** - AEGIS-256 for speed, AES-256-GCM for compatibility

## Troubleshooting

### Common Issues

1. **Connection refused**: Make sure the Fortress server is running
2. **Authentication errors**: Check your credentials and token format
3. **Rate limiting**: Implement backoff and retry logic
4. **Large payloads**: Check `max_body_size` configuration
5. **Field encryption errors**: Verify algorithm names and key IDs

### Debug Mode

Enable debug logging by setting the `RUST_LOG` environment variable:

```bash
export RUST_LOG=debug
cargo run --bin fortress-server
```

This will provide detailed logging for troubleshooting API issues.
