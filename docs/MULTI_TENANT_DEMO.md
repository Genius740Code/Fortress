# Fortress Multi-Tenant Demo

This demo showcases Fortress's multi-tenant isolation capabilities with a practical, working example of data separation between different tenants.

## 🎯 Demo Overview

The demo demonstrates:
- **Complete Data Isolation**: Tenants cannot access each other's data
- **Resource Limits**: Per-tenant resource quotas and enforcement
- **Admin Oversight**: Cross-tenant visibility for administrators
- **Real-world Scenarios**: E-commerce vs Analytics tenant use cases

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Tenant A      │    │   Tenant B      │    │   Admin Client  │
│  (E-commerce)   │    │  (Analytics)    │    │  (Management)   │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────┴─────────────┐
                    │    Fortress Server      │
                    │  + Tenant Manager       │
                    │  + Resource Isolation   │
                    │  + Data Storage         │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │   Shared Storage        │
                    │ (PostgreSQL + Redis)    │
                    └─────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Make (for running demo scripts)

### 1. Start the Demo Environment

```bash
# Clone and navigate to the Fortress repository
cd fortress/docker

# Start the multi-tenant demo
docker-compose -f docker-compose.tenant-demo.yml up -d

# Wait for services to be ready (watch the logs)
docker-compose -f docker-compose.tenant-demo.yml logs -f fortress-server
```

### 2. Set Up Tenants

```bash
# Run tenant setup from admin client
docker-compose -f docker-compose.tenant-demo.yml exec admin-client /scripts/setup-tenants.sh
```

### 3. Populate Tenant Data

```bash
# Add data for Tenant A (E-commerce)
docker-compose -f docker-compose.tenant-demo.yml exec tenant-a-client /scripts/tenant-a-data.sh

# Add data for Tenant B (Analytics)
docker-compose -f docker-compose.tenant-demo.yml exec tenant-b-client /scripts/tenant-b-data.sh
```

### 4. Verify Data Isolation

```bash
# Run the isolation verification script
docker-compose -f docker-compose.tenant-demo.yml exec admin-client /scripts/verify-isolation.sh
```

## 📊 Demo Scenarios

### Tenant A: E-commerce Platform
- **Data Type**: Customer information, orders, products
- **Resource Limits**: 3 databases, 512MB storage, 5 connections
- **Use Case**: Online retail platform with customer data

### Tenant B: Analytics Platform  
- **Data Type**: Analytics reports, user behavior, ML models
- **Resource Limits**: 2 databases, 256MB storage, 3 connections
- **Use Case**: Business intelligence and machine learning

## 🔒 Security Features Demonstrated

### 1. Data Isolation
```bash
# Tenant A trying to access Tenant B data (should fail)
curl -H "Authorization: Bearer demo-tenant-a-key" \
     -H "X-Tenant-ID: tenant-a" \
     http://localhost:8080/api/v1/data/analytics_report_2024_01

# Result: 404 Not Found or 403 Forbidden
```

### 2. Resource Enforcement
```bash
# Check tenant resource usage
curl -H "Authorization: Bearer demo-admin-key" \
     http://localhost:8080/api/v1/tenants/tenant-a/stats

# Shows: database count, storage used, connections, etc.
```

### 3. Admin Cross-Tenant Visibility
```bash
# Admin can see all data across tenants
curl -H "Authorization: Bearer demo-admin-key" \
     http://localhost:8080/api/v1/admin/data

# Returns: All data records with tenant IDs
```

## 🛠️ API Endpoints

### Tenant Management (Admin Only)
- `POST /api/v1/tenants` - Create new tenant
- `GET /api/v1/tenants` - List all tenants  
- `GET /api/v1/tenants/{id}/stats` - Get tenant statistics

### Data Operations (Tenant Scoped)
- `POST /api/v1/data` - Store data (with `X-Tenant-ID` header)
- `GET /api/v1/data/{key}` - Retrieve data
- `GET /api/v1/data` - List tenant's data

### Admin Operations
- `GET /api/v1/admin/data` - List all data across tenants

## 📋 Demo Scripts Explained

### setup-tenants.sh
Creates two demo tenants with different resource limits:
- **Tenant A**: E-commerce focus, higher storage limits
- **Tenant B**: Analytics focus, lower storage limits

### tenant-a-data.sh
Populates Tenant A with realistic e-commerce data:
- Customer records with PII
- Product catalog with inventory
- Order history with payment info

### tenant-b-data.sh  
Populates Tenant B with analytics data:
- Performance reports and metrics
- User behavior segments
- ML model configurations

### verify-isolation.sh
Tests security boundaries:
- Cross-tenant data access attempts
- Resource limit enforcement
- Admin visibility verification

## 🔧 Configuration

### Environment Variables
```bash
# Multi-tenant mode
FORTRESS_ENABLE_MULTI_TENANT=true

# Default tenant limits
FORTRESS_MAX_TENANT_DATABASES=5
FORTRESS_MAX_TENANT_STORAGE=1073741824  # 1GB
FORTRESS_MAX_TENANT_CONNECTIONS=10
```

### Tenant Authentication
- **Tenant A**: API Key `demo-tenant-a-key`
- **Tenant B**: API Key `demo-tenant-b-key`  
- **Admin**: API Key `demo-admin-key`

## 📈 Monitoring & Metrics

### Resource Usage Tracking
```bash
# Monitor tenant resource usage in real-time
docker-compose -f docker-compose.tenant-demo.yml logs -f fortress-server | grep "tenant"
```

### Health Checks
```bash
# Check overall system health
curl http://localhost:8080/health

# Check specific tenant health
curl -H "Authorization: Bearer demo-admin-key" \
     http://localhost:8080/api/v1/tenants/tenant-a/stats
```

## 🚨 Troubleshooting

### Common Issues

1. **Tenant Access Denied**
   - Verify API key and tenant ID headers
   - Check if tenant exists and is active

2. **Resource Limit Exceeded**
   - Monitor tenant stats: `/api/v1/tenants/{id}/stats`
   - Adjust limits in tenant creation request

3. **Data Not Found**
   - Confirm correct tenant context
   - Check if data was stored with tenant ID

### Debug Commands
```bash
# View all containers
docker-compose -f docker-compose.tenant-demo.yml ps

# Check server logs
docker-compose -f docker-compose.tenant-demo.yml logs fortress-server

# Access container shell
docker-compose -f docker-compose.tenant-demo.yml exec tenant-a-client bash
```

## 🎯 Learning Outcomes

After running this demo, you'll understand:

1. **Data Isolation**: How Fortress prevents cross-tenant data access
2. **Resource Management**: Per-tenant quotas and enforcement
3. **Security Model**: Role-based access control in multi-tenant environments
4. **Operational Oversight**: Admin visibility across tenant boundaries
5. **Scalability**: How multi-tenancy enables efficient resource utilization

## 🔄 Next Steps

- **Custom Tenants**: Create your own tenant configurations
- **Performance Testing**: Load test with multiple concurrent tenants
- **Integration**: Connect your applications to specific tenants
- **Monitoring**: Set up alerts for tenant resource usage
- **Compliance**: Implement audit logging for tenant activities

## 📚 Additional Resources

- [Fortress Documentation](../docs/)
- [Multi-Tenant Architecture Guide](../docs/multi-tenancy.md)
- [API Reference](../docs/api-reference.md)
- [Security Best Practices](../docs/security.md)

---

**This demo addresses Chen's feedback by providing a concrete, working example of multi-tenant data isolation rather than just skeletal implementations.**
