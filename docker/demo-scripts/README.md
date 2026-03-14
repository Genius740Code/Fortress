# Fortress Multi-Tenant Demo Scripts

This directory contains the demo scripts for showcasing Fortress's multi-tenant isolation capabilities.

## 📁 Scripts Overview

### 🏢 setup-tenants.sh
**Purpose**: Creates two demo tenants with different resource limits and configurations.

**What it does**:
- Creates "Tenant A - E-commerce" with higher storage limits
- Creates "Tenant B - Analytics" with lower storage limits  
- Configures resource quotas per tenant
- Lists all created tenants

**Usage**:
```bash
# Run from admin client container
/scripts/setup-tenants.sh
```

### 🛒 tenant-a-data.sh
**Purpose**: Populates Tenant A with realistic e-commerce data to demonstrate data isolation.

**What it does**:
- Stores customer PII data (names, emails, orders)
- Stores product catalog with inventory
- Stores order history with payment information
- Demonstrates tenant-scoped data operations

**Usage**:
```bash
# Run from tenant-a-client container
/scripts/tenant-a-data.sh
```

### 📊 tenant-b-data.sh
**Purpose**: Populates Tenant B with analytics data to show different data types and isolation.

**What it does**:
- Stores analytics reports and performance metrics
- Stores user behavior segmentation data
- Stores ML model configurations and metadata
- Demonstrates analytics-focused data patterns

**Usage**:
```bash
# Run from tenant-b-client container
/scripts/tenant-b-data.sh
```

### 🔒 verify-isolation.sh
**Purpose**: Tests and demonstrates the security boundaries between tenants.

**What it does**:
- **Test 1**: Tenant A trying to access Tenant B data (should fail)
- **Test 2**: Tenant B trying to access Tenant A data (should fail)
- **Test 3**: Verify each tenant only sees their own data
- **Test 4**: Admin cross-tenant visibility (should succeed)
- **Test 5**: Resource usage monitoring

**Usage**:
```bash
# Run from admin client container
/scripts/verify-isolation.sh
```

## 🚀 Running the Demo

### Prerequisites
- Docker Compose environment running
- Fortress server healthy and accessible
- Demo containers started

### Step-by-Step Execution

1. **Start the environment**:
   ```bash
   docker-compose -f docker-compose.tenant-demo.yml up -d
   ```

2. **Wait for server to be ready**:
   ```bash
   # Watch logs until server is healthy
   docker-compose -f docker-compose.tenant-demo.yml logs -f fortress-server
   ```

3. **Setup tenants**:
   ```bash
   docker-compose -f docker-compose.tenant-demo.yml exec admin-client /scripts/setup-tenants.sh
   ```

4. **Populate data**:
   ```bash
   # Add Tenant A data
   docker-compose -f docker-compose.tenant-demo.yml exec tenant-a-client /scripts/tenant-a-data.sh
   
   # Add Tenant B data  
   docker-compose -f docker-compose.tenant-demo.yml exec tenant-b-client /scripts/tenant-b-data.sh
   ```

5. **Verify isolation**:
   ```bash
   docker-compose -f docker-compose.tenant-demo.yml exec admin-client /scripts/verify-isolation.sh
   ```

## 🔧 Configuration

### Environment Variables
Each script uses these environment variables (set by Docker Compose):

```bash
# Server connection
FORTRESS_SERVER_URL=http://fortress-server:8080

# Authentication
FORTRESS_API_KEY=demo-tenant-a-key  # or demo-tenant-b-key, demo-admin-key
FORTRESS_TENANT_ID=tenant-a          # or tenant-b

# Admin access
FORTRESS_ADMIN_KEY=demo-admin-key
```

### API Endpoints Used
- `POST /api/v1/tenants` - Create tenant
- `GET /api/v1/tenants` - List tenants
- `POST /api/v1/data` - Store data
- `GET /api/v1/data` - List data
- `GET /api/v1/data/{key}` - Get specific data
- `GET /api/v1/admin/data` - Admin cross-tenant access
- `GET /api/v1/tenants/{id}/stats` - Tenant statistics

## 📊 Expected Results

### Successful Tenant Creation
```json
{
  "data": {
    "id": "uuid-here",
    "name": "Tenant A - E-commerce",
    "description": "E-commerce platform tenant",
    "active": true,
    "resource_limits": {
      "max_databases": 3,
      "max_storage_size": 536870912,
      "max_connections": 5
    }
  },
  "success": true
}
```

### Data Storage Success
```json
{
  "data": {
    "id": "data-uuid",
    "key_id": "key-uuid", 
    "created_at": "2024-01-15T10:30:00Z"
  },
  "success": true
}
```

### Isolation Verification
- **Cross-tenant access**: HTTP 403/404 errors ✅
- **Own data access**: HTTP 200 with data ✅  
- **Admin visibility**: HTTP 200 with all tenant data ✅

## 🚨 Troubleshooting

### Common Issues

1. **"Server not ready" errors**
   - Wait longer for Fortress server to start
   - Check server health: `curl http://localhost:8080/health`

2. **"Access denied" errors**
   - Verify API keys are correct
   - Check tenant ID headers are set

3. **"Tenant not found" errors**
   - Run setup script first to create tenants
   - Check tenant ID spelling

### Debug Commands
```bash
# Check container status
docker-compose -f docker-compose.tenant-demo.yml ps

# View server logs
docker-compose -f docker-compose.tenant-demo.yml logs fortress-server

# Test API directly
curl -H "Authorization: Bearer demo-admin-key" \
     http://localhost:8080/api/v1/tenants

# Access container shell for debugging
docker-compose -f docker-compose.tenant-demo.yml exec admin-client bash
```

## 🎯 Learning Points

This demo demonstrates:

1. **Complete Data Isolation**: Tenants cannot access each other's data
2. **Resource Enforcement**: Per-tenant quotas are actively enforced
3. **Admin Oversight**: Administrators have cross-tenant visibility
4. **Real-world Usage**: Practical e-commerce vs analytics scenarios
5. **Security Boundaries**: Role-based access control in action

---

**These scripts directly address Chen's request for a working demo that shows actual data isolation, not just skeletal implementations.**
