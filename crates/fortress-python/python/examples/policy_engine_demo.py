#!/usr/bin/env python3
"""
Policy engine demo using Fortress Python SDK
"""

import asyncio
import fortress
from datetime import datetime, timedelta


async def main():
    print("🛡️ Fortress Policy Engine Demo")
    print("=" * 40)
    
    # Create policy engine
    policy_engine = fortress.PolicyEngine()
    print("Policy engine created")
    print()
    
    # Define roles
    print("Creating roles...")
    roles = [
        {
            "name": "admin",
            "description": "Full administrative access",
            "permissions": ["*"]  # All permissions
        },
        {
            "name": "developer",
            "description": "Developer access",
            "permissions": [
                "encrypt:*",
                "decrypt:*",
                "key:generate",
                "key:list",
                "key:get"
            ]
        },
        {
            "name": "analyst",
            "description": "Data analyst access",
            "permissions": [
                "decrypt:analytics_data",
                "encrypt:analytics_data",
                "key:get:analytics_keys"
            ]
        },
        {
            "name": "auditor",
            "description": "Audit access only",
            "permissions": [
                "audit:read",
                "policy:read"
            ]
        }
    ]
    
    created_roles = {}
    for role_data in roles:
        role = fortress.RoleWrapper(
            name=role_data["name"],
            description=role_data["description"],
            permissions=[
                fortress.PermissionWrapper.from_string(perm) 
                for perm in role_data["permissions"]
            ]
        )
        
        role_id = await policy_engine.create_role(role)
        created_roles[role_data["name"]] = role_id
        print(f"  Created role: {role_data['name']} (ID: {role_id})")
    
    print()
    
    # Define resources
    print("Creating resources...")
    resources = [
        {
            "name": "user_data",
            "type": "data_collection",
            "description": "User personal data",
            "tags": ["pii", "sensitive"]
        },
        {
            "name": "analytics_data",
            "type": "data_collection", 
            "description": "Analytics and metrics data",
            "tags": ["analytics", "aggregated"]
        },
        {
            "name": "system_keys",
            "type": "key_store",
            "description": "System encryption keys",
            "tags": ["keys", "system"]
        },
        {
            "name": "user_keys",
            "type": "key_store",
            "description": "User-specific encryption keys",
            "tags": ["keys", "user"]
        }
    ]
    
    created_resources = {}
    for resource_data in resources:
        resource = fortress.ResourceWrapper(
            name=resource_data["name"],
            resource_type=resource_data["type"],
            description=resource_data["description"],
            tags=resource_data["tags"]
        )
        
        resource_id = await policy_engine.create_resource(resource)
        created_resources[resource_data["name"]] = resource_id
        print(f"  Created resource: {resource_data['name']} (ID: {resource_id})")
    
    print()
    
    # Create policies
    print("Creating policies...")
    policies = [
        {
            "name": "admin_full_access",
            "description": "Administrators have full access to all resources",
            "effect": "allow",
            "roles": ["admin"],
            "resources": ["*"],
            "actions": ["*"],
            "conditions": {}
        },
        {
            "name": "developer_encryption_access",
            "description": "Developers can encrypt/decrypt data and manage keys",
            "effect": "allow",
            "roles": ["developer"],
            "resources": ["user_data", "analytics_data", "user_keys"],
            "actions": ["encrypt", "decrypt", "key:generate", "key:list"],
            "conditions": {
                "time_range": {
                    "start": "09:00",
                    "end": "18:00"
                }
            }
        },
        {
            "name": "analyst_limited_access",
            "description": "Analysts can only access analytics data",
            "effect": "allow",
            "roles": ["analyst"],
            "resources": ["analytics_data"],
            "actions": ["encrypt", "decrypt"],
            "conditions": {
                "ip_whitelist": ["192.168.1.0/24", "10.0.0.0/8"]
            }
        },
        {
            "name": "deny_pii_access",
            "description": "Deny access to PII data for non-admins",
            "effect": "deny",
            "roles": ["developer", "analyst", "auditor"],
            "resources": ["user_data"],
            "actions": ["*"],
            "conditions": {
                "data_classification": "pii"
            }
        }
    ]
    
    created_policies = {}
    for policy_data in policies:
        policy = await policy_engine.create_policy(
            name=policy_data["name"],
            description=policy_data["description"],
            effect=policy_data["effect"],
            roles=[created_roles[role] for role in policy_data["roles"]],
            resources=[
                created_resources[res] if res != "*" else "*"
                for res in policy_data["resources"]
            ],
            actions=policy_data["actions"],
            conditions=policy_data["conditions"]
        )
        
        created_policies[policy_data["name"]] = policy
        print(f"  Created policy: {policy_data['name']}")
    
    print()
    
    # Test policy evaluations
    print("Testing policy evaluations...")
    test_scenarios = [
        {
            "user_role": "admin",
            "action": "encrypt",
            "resource": "user_data",
            "context": {"ip": "192.168.1.100", "time": "10:00"}
        },
        {
            "user_role": "developer",
            "action": "encrypt",
            "resource": "user_data",
            "context": {"ip": "192.168.1.100", "time": "10:00"}
        },
        {
            "user_role": "developer",
            "action": "decrypt",
            "resource": "analytics_data",
            "context": {"ip": "192.168.1.100", "time": "14:00"}
        },
        {
            "user_role": "analyst",
            "action": "decrypt",
            "resource": "analytics_data",
            "context": {"ip": "192.168.1.100", "time": "15:00"}
        },
        {
            "user_role": "analyst",
            "action": "encrypt",
            "resource": "user_data",
            "context": {"ip": "192.168.1.100", "time": "15:00"}
        },
        {
            "user_role": "auditor",
            "action": "audit:read",
            "resource": "*",
            "context": {"ip": "10.0.0.50", "time": "16:00"}
        }
    ]
    
    for scenario in test_scenarios:
        role_id = created_roles[scenario["user_role"]]
        resource_id = created_resources.get(scenario["resource"], "*")
        
        result = await policy_engine.evaluate_policy(
            role_id=role_id,
            action=scenario["action"],
            resource_id=resource_id,
            context=scenario["context"]
        )
        
        status = "✅ ALLOW" if result.allowed else "❌ DENY"
        print(f"  {scenario['user_role']} -> {scenario['action']} on {scenario['resource']}: {status}")
        
        if not result.allowed and result.reason:
            print(f"    Reason: {result.reason}")
    
    print()
    
    # Test with time-based conditions
    print("Testing time-based conditions...")
    current_time = datetime.now().time()
    
    # Developer trying to access outside business hours
    after_hours_context = {
        "time": "20:00",  # 8 PM
        "ip": "192.168.1.100"
    }
    
    result = await policy_engine.evaluate_policy(
        role_id=created_roles["developer"],
        action="encrypt",
        resource_id=created_resources["user_data"],
        context=after_hours_context
    )
    
    status = "✅ ALLOW" if result.allowed else "❌ DENY"
    print(f"  Developer after hours access: {status}")
    if not result.allowed:
        print(f"    Reason: {result.reason}")
    
    print()
    
    # List all policies
    print("Listing all policies...")
    all_policies = await policy_engine.list_policies()
    for policy in all_policies:
        print(f"  - {policy.name}: {policy.effect}")
    
    print()
    
    # Clean up
    print("Cleaning up policies...")
    for policy_name, policy_id in created_policies.items():
        await policy_engine.delete_policy(policy_id)
        print(f"  Deleted policy: {policy_name}")
    
    print("Cleaning up resources...")
    for resource_name, resource_id in created_resources.items():
        await policy_engine.delete_resource(resource_id)
        print(f"  Deleted resource: {resource_name}")
    
    print("Cleaning up roles...")
    for role_name, role_id in created_roles.items():
        await policy_engine.delete_role(role_id)
        print(f"  Deleted role: {role_name}")
    
    print()
    print("🎉 Policy engine demo completed successfully!")


if __name__ == "__main__":
    asyncio.run(main())
