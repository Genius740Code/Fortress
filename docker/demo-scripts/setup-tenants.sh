#!/bin/bash

# Multi-Tenant Demo Setup Script
# This script sets up two tenants and demonstrates data isolation

set -e

echo "🏢 Fortress Multi-Tenant Demo Setup"
echo "=================================="

# Wait for server to be ready
echo "⏳ Waiting for Fortress server..."
until curl -f http://fortress-server:8080/health > /dev/null 2>&1; do
    echo "Server not ready, waiting..."
    sleep 2
done
echo "✅ Fortress server is ready!"

# Create Tenant A
echo ""
echo "🏢 Creating Tenant A..."
curl -X POST http://fortress-server:8080/api/v1/tenants \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer demo-admin-key" \
    -d '{
        "name": "Tenant A - E-commerce",
        "description": "E-commerce platform tenant",
        "resource_limits": {
            "max_databases": 3,
            "max_storage_size": 536870912,
            "max_connections": 5
        }
    }' | jq '.'

# Create Tenant B
echo ""
echo "🏢 Creating Tenant B..."
curl -X POST http://fortress-server:8080/api/v1/tenants \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer demo-admin-key" \
    -d '{
        "name": "Tenant B - Analytics",
        "description": "Data analytics platform tenant", 
        "resource_limits": {
            "max_databases": 2,
            "max_storage_size": 268435456,
            "max_connections": 3
        }
    }' | jq '.'

# List all tenants
echo ""
echo "📋 Listing all tenants..."
curl -X GET http://fortress-server:8080/api/v1/tenants \
    -H "Authorization: Bearer demo-admin-key" | jq '.'

echo ""
echo "✅ Tenant setup complete!"
echo "Next, run the data isolation demo scripts."
