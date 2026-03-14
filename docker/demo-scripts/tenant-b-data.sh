#!/bin/bash

# Tenant B Data Operations Demo
# This script demonstrates data operations for Tenant B

set -e

TENANT_ID="tenant-b"
API_KEY="demo-tenant-b-key"
BASE_URL="http://fortress-server:8080"

echo "📊 Tenant B - Analytics Data Demo"
echo "==============================="

# Store analytics data
echo ""
echo "📈 Storing analytics data for Tenant B..."
curl -X POST $BASE_URL/api/v1/data \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -H "X-Tenant-ID: $TENANT_ID" \
    -d '{
        "key": "analytics_report_2024_01",
        "data": {
            "report_type": "monthly_performance",
            "period": "2024-01",
            "metrics": {
                "total_users": 15420,
                "active_sessions": 3280,
                "conversion_rate": 0.034,
                "revenue": 45780.50,
                "bounce_rate": 0.42
            },
            "segments": {
                "mobile": {"users": 8900, "revenue": 23400.00},
                "desktop": {"users": 6520, "revenue": 22380.50}
            },
            "trends": {
                "user_growth": 0.12,
                "revenue_growth": 0.08
            }
        },
        "metadata": {
            "source": "analytics_engine",
            "generated_at": "2024-02-01T00:00:00Z",
            "classification": "business_metrics"
        }
    }' | jq '.'

# Store user behavior data
echo ""
echo "👥 Storing user behavior data for Tenant B..."
curl -X POST $BASE_URL/api/v1/data \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -H "X-Tenant-ID: $TENANT_ID" \
    -d '{
        "key": "user_behavior_segment_premium",
        "data": {
            "segment_name": "premium_users",
            "user_count": 1250,
            "characteristics": {
                "avg_session_duration": 480,
                "pages_per_session": 8.5,
                "cart_conversion_rate": 0.089,
                "avg_order_value": 156.78
            },
            "preferences": {
                "top_categories": ["electronics", "fashion", "home"],
                "device_preference": "mobile",
                "peak_activity_hours": ["19:00", "20:00", "21:00"]
            },
            "retention": {
                "day_7": 0.78,
                "day_30": 0.65,
                "day_90": 0.42
            }
        },
        "metadata": {
            "source": "behavioral_analytics",
            "last_updated": "2024-01-31T23:59:59Z"
        }
    }' | jq '.'

# Store ML model data
echo ""
echo "🤖 Storing ML model data for Tenant B..."
curl -X POST $BASE_URL/api/v1/data \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -H "X-Tenant-ID: $TENANT_ID" \
    -d '{
        "key": "ml_model_recommendation_v2",
        "data": {
            "model_name": "product_recommendation_v2",
            "version": "2.1.0",
            "model_type": "collaborative_filtering",
            "performance": {
                "precision": 0.82,
                "recall": 0.79,
                "f1_score": 0.80,
                "auc": 0.91
            },
            "features": [
                "user_purchase_history",
                "browsing_behavior", 
                "demographic_data",
                "seasonal_patterns"
            ],
            "training_data": {
                "samples": 125000,
                "training_period": "2023-01-01 to 2023-12-31",
                "validation_split": 0.2
            },
            "deployment": {
                "environment": "production",
                "last_deployed": "2024-01-15T14:30:00Z",
                "predictions_per_day": 45000
            }
        },
        "metadata": {
            "source": "ml_platform",
            "model_registry_id": "model_789",
            "classification": "proprietary_algorithm"
        }
    }' | jq '.'

# List all data for Tenant B
echo ""
echo "📋 Listing all data for Tenant B..."
curl -X GET "$BASE_URL/api/v1/data?tenant_id=$TENANT_ID" \
    -H "Authorization: Bearer $API_KEY" \
    -H "X-Tenant-ID: $TENANT_ID" | jq '.'

echo ""
echo "✅ Tenant B data operations complete!"
echo "Tenant B has stored analytics, user behavior, and ML model data."
