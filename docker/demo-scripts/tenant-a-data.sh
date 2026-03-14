#!/bin/bash

# Tenant A Data Operations Demo
# This script demonstrates data operations for Tenant A

set -e

TENANT_ID="tenant-a"
API_KEY="demo-tenant-a-key"
BASE_URL="http://fortress-server:8080"

echo "🛒 Tenant A - E-commerce Data Demo"
echo "================================="

# Store customer data
echo ""
echo "📦 Storing customer data for Tenant A..."
curl -X POST $BASE_URL/api/v1/data \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -H "X-Tenant-ID: $TENANT_ID" \
    -d '{
        "key": "customer_12345",
        "data": {
            "name": "John Doe",
            "email": "john@tenant-a-ecommerce.com",
            "orders": [
                {"id": "ORD001", "amount": 99.99, "status": "completed"},
                {"id": "ORD002", "amount": 149.99, "status": "shipped"}
            ],
            "total_spent": 249.98,
            "loyalty_tier": "gold"
        },
        "metadata": {
            "source": "customer_service",
            "classification": "pii"
        }
    }' | jq '.'

# Store product data
echo ""
echo "📦 Storing product data for Tenant A..."
curl -X POST $BASE_URL/api/v1/data \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -H "X-Tenant-ID: $TENANT_ID" \
    -d '{
        "key": "product_prod_789",
        "data": {
            "name": "Premium Widget",
            "price": 89.99,
            "inventory": 150,
            "category": "electronics",
            "tags": ["premium", "bestseller", "electronics"],
            "specifications": {
                "weight": "2.5kg",
                "dimensions": "30x20x10cm",
                "warranty": "2 years"
            }
        },
        "metadata": {
            "source": "inventory_system",
            "last_updated": "2024-01-15T10:30:00Z"
        }
    }' | jq '.'

# Store order data
echo ""
echo "📦 Storing order data for Tenant A..."
curl -X POST $BASE_URL/api/v1/data \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -H "X-Tenant-ID: $TENANT_ID" \
    -d '{
        "key": "order_ORD003",
        "data": {
            "customer_id": "customer_12345",
            "items": [
                {"product_id": "product_prod_789", "quantity": 2, "price": 89.99}
            ],
            "total_amount": 179.98,
            "status": "processing",
            "shipping_address": {
                "street": "123 Commerce St",
                "city": "Business City",
                "country": "USA"
            }
        },
        "metadata": {
            "source": "order_system",
            "priority": "high"
        }
    }' | jq '.'

# List all data for Tenant A
echo ""
echo "📋 Listing all data for Tenant A..."
curl -X GET "$BASE_URL/api/v1/data?tenant_id=$TENANT_ID" \
    -H "Authorization: Bearer $API_KEY" \
    -H "X-Tenant-ID: $TENANT_ID" | jq '.'

echo ""
echo "✅ Tenant A data operations complete!"
echo "Tenant A has stored customer, product, and order data."
