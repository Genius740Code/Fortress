#!/usr/bin/env python3
"""
Multi-tenant demo using Fortress Python SDK
"""

import asyncio
import fortress
from datetime import datetime


async def main():
    print("🏢 Fortress Multi-Tenant Demo")
    print("=" * 40)
    
    # Create tenant manager
    tenant_manager = fortress.TenantManager()
    print("Tenant manager created")
    print()
    
    # Create tenants
    tenants = []
    tenant_configs = [
        {
            "name": "Acme Corp",
            "domain": "acme.com",
            "plan": "enterprise",
            "limits": {
                "max_keys": 1000,
                "max_storage_gb": 100,
                "max_api_calls_per_day": 100000
            }
        },
        {
            "name": "Startup Inc",
            "domain": "startup.io", 
            "plan": "startup",
            "limits": {
                "max_keys": 100,
                "max_storage_gb": 10,
                "max_api_calls_per_day": 10000
            }
        },
        {
            "name": "Dev Team",
            "domain": "dev.local",
            "plan": "development",
            "limits": {
                "max_keys": 50,
                "max_storage_gb": 5,
                "max_api_calls_per_day": 5000
            }
        }
    ]
    
    print("Creating tenants...")
    for config in tenant_configs:
        tenant_request = fortress.CreateTenantRequestWrapper(
            name=config["name"],
            domain=config["domain"],
            plan=config["plan"],
            resource_limits=fortress.TenantResourceLimitsWrapper(**config["limits"])
        )
        
        tenant_id = await tenant_manager.create_tenant(tenant_request)
        tenants.append((tenant_id, config))
        print(f"  Created tenant: {config['name']} (ID: {tenant_id})")
    
    print()
    print(f"Created {len(tenants)} tenants")
    print()
    
    # List all tenants
    print("Listing all tenants...")
    all_tenants = await tenant_manager.list_tenants()
    for tenant in all_tenants:
        print(f"  - {tenant.name} ({tenant.domain}) - {tenant.plan}")
    print()
    
    # Simulate tenant operations
    print("Simulating tenant operations...")
    for tenant_id, config in tenants:
        print(f"\n--- {config['name']} Operations ---")
        
        # Create tenant-specific key manager
        key_manager = fortress.KeyManager(tenant_id=tenant_id)
        
        # Generate keys for the tenant
        key_metadata = {
            "tenant_id": tenant_id,
            "purpose": "data-encryption",
            "created_by": "demo-script",
            "tags": [config["plan"], "demo"]
        }
        
        key_id = await key_manager.generate_key("aegis256", key_metadata)
        print(f"Generated key: {key_id}")
        
        # Test encryption with tenant key
        algorithm = fortress.EncryptionAlgorithm.aegis256()
        key_data = await key_manager.get_key(key_id)
        
        tenant_data = f"Secret data for {config['name']}".encode()
        ciphertext = await algorithm.encrypt(tenant_data, key_data)
        decrypted = await algorithm.decrypt(ciphertext, key_data)
        
        print(f"Encrypted/decrypted tenant data: {decrypted.decode()}")
        
        # Get tenant statistics
        try:
            stats = await tenant_manager.get_tenant_stats(tenant_id)
            print(f"Tenant stats: {stats.key_count} keys, {stats.storage_used_mb} MB used")
        except:
            print("Tenant stats not available")
        
        # Clean up tenant key
        await key_manager.delete_key(key_id)
        print("Cleaned up tenant key")
    
    print()
    
    # Update tenant limits
    print("Updating tenant limits...")
    acme_tenant_id = tenants[0][0]
    update_request = fortress.UpdateTenantRequestWrapper(
        resource_limits=fortress.TenantResourceLimitsWrapper(
            max_keys=2000,
            max_storage_gb=200,
            max_api_calls_per_day=200000
        )
    )
    
    await tenant_manager.update_tenant(acme_tenant_id, update_request)
    print(f"Updated limits for {tenants[0][1]['name']}")
    print()
    
    # Clean up tenants
    print("Cleaning up tenants...")
    for tenant_id, config in tenants:
        await tenant_manager.delete_tenant(tenant_id)
        print(f"Deleted tenant: {config['name']}")
    
    print()
    print("🎉 Multi-tenant demo completed successfully!")


if __name__ == "__main__":
    asyncio.run(main())
