//! Tenant management commands for Fortress CLI

use clap::Subcommand;
use color_eyre::eyre::Result;
use fortress_core::{
    tenant::{
        TenantManager, InMemoryTenantManager, CreateTenantRequest,
        TenantResourceLimits, GlobalResourceLimits
    },
};
use std::str::FromStr;
use uuid::Uuid;
use dialoguer::Confirm;

/// Tenant management commands
#[derive(Debug, Subcommand)]
pub enum TenantCommands {
    /// Create a new tenant
    Create {
        /// Tenant name
        #[arg(short, long)]
        name: String,
        
        /// Tenant description
        #[arg(short, long)]
        description: Option<String>,
        
        /// Maximum databases allowed
        #[arg(long)]
        max_databases: Option<u32>,
        
        /// Maximum storage size in bytes
        #[arg(long)]
        max_storage: Option<u64>,
        
        /// Maximum connections allowed
        #[arg(long)]
        max_connections: Option<u32>,
    },
    /// List all tenants
    List,
    /// Show tenant details
    Show {
        /// Tenant ID
        tenant_id: String,
    },
    /// Show tenant statistics
    Stats {
        /// Tenant ID
        tenant_id: String,
    },
    /// Delete a tenant
    Delete {
        /// Tenant ID
        tenant_id: String,
        /// Force deletion (skip confirmation)
        #[arg(long)]
        force: bool,
    },
}

/// Execute tenant commands
pub async fn execute_tenant_command(command: TenantCommands) -> Result<()> {
    // Create tenant manager with default global limits
    let global_limits = GlobalResourceLimits::default();
    let tenant_manager = InMemoryTenantManager::with_global_limits(global_limits);
    
    match command {
        TenantCommands::Create { name, description, max_databases, max_storage, max_connections } => {
            create_tenant(&tenant_manager, name, description, max_databases, max_storage, max_connections).await
        }
        TenantCommands::List => {
            list_tenants(&tenant_manager).await
        }
        TenantCommands::Show { tenant_id } => {
            show_tenant(&tenant_manager, &tenant_id).await
        }
        TenantCommands::Stats { tenant_id } => {
            show_tenant_stats(&tenant_manager, &tenant_id).await
        }
        TenantCommands::Delete { tenant_id, force } => {
            delete_tenant(&tenant_manager, &tenant_id, force).await
        }
    }
}

/// Create a new tenant
async fn create_tenant(
    manager: &InMemoryTenantManager,
    name: String,
    description: Option<String>,
    max_databases: Option<u32>,
    max_storage: Option<u64>,
    max_connections: Option<u32>,
) -> Result<()> {
    println!("🏢 Creating new tenant...");
    
    let resource_limits = if max_databases.is_some() || max_storage.is_some() || max_connections.is_some() {
        Some(TenantResourceLimits {
            max_databases,
            max_storage_size: max_storage,
            max_connections,
            cpu_quota: None,
            memory_quota: None,
        })
    } else {
        None
    };
    
    let request = CreateTenantRequest {
        name: name.clone(),
        description,
        encryption_config: None,
        resource_limits,
    };
    
    match manager.create_tenant(request).await {
        Ok(tenant) => {
            println!("✅ Tenant created successfully!");
            println!("📋 Tenant ID: {}", tenant.id);
            println!("📝 Name: {}", tenant.name);
            if let Some(desc) = tenant.description {
                println!("📄 Description: {}", desc);
            }
            if let Some(limits) = tenant.resource_limits.max_databases {
                println!("🗄️  Max databases: {}", limits);
            }
            if let Some(storage) = tenant.resource_limits.max_storage_size {
                println!("💾 Max storage: {} bytes", storage);
            }
            if let Some(connections) = tenant.resource_limits.max_connections {
                println!("🔗 Max connections: {}", connections);
            }
            println!("📅 Created: {}", tenant.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
        }
        Err(e) => {
            return Err(color_eyre::eyre::eyre!("Failed to create tenant: {}", e));
        }
    }
    
    Ok(())
}

/// List all tenants
async fn list_tenants(manager: &InMemoryTenantManager) -> Result<()> {
    println!("🏢 Fortress Tenants");
    println!("==================");
    
    match manager.list_tenants().await {
        Ok(tenants) => {
            if tenants.is_empty() {
                println!("📭 No tenants found.");
                return Ok(());
            }
            
            println!("📊 Total tenants: {}\n", tenants.len());
            
            for tenant in tenants {
                println!("🏢 {}", tenant.name);
                println!("   📋 ID: {}", tenant.id);
                if let Some(desc) = tenant.description {
                    println!("   📄 Description: {}", desc);
                }
                println!("   ✅ Status: {}", if tenant.active { "Active" } else { "Inactive" });
                println!("   📅 Created: {}", tenant.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
                println!();
            }
        }
        Err(e) => {
            return Err(color_eyre::eyre::eyre!("Failed to list tenants: {}", e));
        }
    }
    
    Ok(())
}

/// Show tenant details
async fn show_tenant(manager: &InMemoryTenantManager, tenant_id_str: &str) -> Result<()> {
    let tenant_id = match Uuid::from_str(tenant_id_str) {
        Ok(id) => id,
        Err(_) => {
            return Err(color_eyre::eyre::eyre!("Invalid tenant ID format"));
        }
    };
    
    println!("🏢 Tenant Details");
    println!("=================");
    
    match manager.get_tenant(&tenant_id).await {
        Ok(Some(tenant)) => {
            println!("📋 ID: {}", tenant.id);
            println!("📝 Name: {}", tenant.name);
            if let Some(desc) = tenant.description {
                println!("📄 Description: {}", desc);
            }
            println!("✅ Status: {}", if tenant.active { "Active" } else { "Inactive" });
            
            println!("\n📊 Resource Limits:");
            if let Some(max_dbs) = tenant.resource_limits.max_databases {
                println!("   🗄️  Max databases: {}", max_dbs);
            }
            if let Some(max_storage) = tenant.resource_limits.max_storage_size {
                println!("   💾 Max storage: {} bytes", max_storage);
            }
            if let Some(max_conns) = tenant.resource_limits.max_connections {
                println!("   🔗 Max connections: {}", max_conns);
            }
            if let Some(cpu_quota) = tenant.resource_limits.cpu_quota {
                println!("   🖥️  CPU quota: {}%", cpu_quota);
            }
            if let Some(mem_quota) = tenant.resource_limits.memory_quota {
                println!("   🧠 Memory quota: {}%", mem_quota);
            }
            
            println!("\n📅 Timestamps:");
            println!("   🕐 Created: {}", tenant.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
            println!("   🔄 Modified: {}", tenant.modified_at.format("%Y-%m-%d %H:%M:%S UTC"));
        }
        Ok(None) => {
            println!("❌ Tenant not found");
        }
        Err(e) => {
            return Err(color_eyre::eyre::eyre!("Failed to get tenant: {}", e));
        }
    }
    
    Ok(())
}

/// Show tenant statistics
async fn show_tenant_stats(manager: &InMemoryTenantManager, tenant_id_str: &str) -> Result<()> {
    let tenant_id = match Uuid::from_str(tenant_id_str) {
        Ok(id) => id,
        Err(_) => {
            return Err(color_eyre::eyre::eyre!("Invalid tenant ID format"));
        }
    };
    
    println!("📊 Tenant Statistics");
    println!("====================");
    
    match manager.get_tenant_stats(&tenant_id).await {
        Ok(stats) => {
            println!("🗄️  Databases: {}", stats.database_count);
            println!("💾 Storage used: {} bytes", stats.storage_used);
            println!("🔗 Active connections: {}", stats.active_connections);
            println!("🖥️  CPU usage: {:.2}%", stats.cpu_usage);
            println!("🧠 Memory usage: {:.2}%", stats.memory_usage);
            
            // Also show resource usage from isolation manager
            if let Ok(Some(usage)) = manager.resource_isolation().get_tenant_usage(&tenant_id).await {
                println!("\n📈 Resource Usage Details:");
                println!("   🗄️  Database count: {}", usage.database_count);
                println!("   💾 Storage allocated: {} bytes", usage.storage_used);
                println!("   🔗 Active connections: {}", usage.active_connections);
                println!("   🖥️  CPU usage: {:.2}%", usage.cpu_usage);
                println!("   🧠 Memory usage: {:.2}%", usage.memory_usage);
                println!("   🕐 Last updated: {}", usage.last_updated.format("%Y-%m-%d %H:%M:%S UTC"));
            }
        }
        Err(e) => {
            return Err(color_eyre::eyre::eyre!("Failed to get tenant stats: {}", e));
        }
    }
    
    Ok(())
}

/// Delete a tenant
async fn delete_tenant(manager: &InMemoryTenantManager, tenant_id_str: &str, force: bool) -> Result<()> {
    let tenant_id = match Uuid::from_str(tenant_id_str) {
        Ok(id) => id,
        Err(_) => {
            return Err(color_eyre::eyre::eyre!("Invalid tenant ID format"));
        }
    };
    
    // First, show tenant details
    if let Ok(Some(tenant)) = manager.get_tenant(&tenant_id).await {
        println!("🏢 Tenant to delete:");
        println!("   📋 ID: {}", tenant.id);
        println!("   📝 Name: {}", tenant.name);
        if let Some(desc) = tenant.description {
            println!("   📄 Description: {}", desc);
        }
        println!();
    } else {
        println!("❌ Tenant not found");
        return Ok(());
    }
    
    // Confirm deletion unless forced
    if !force {
        if !Confirm::new()
            .with_prompt("⚠️  Are you sure you want to delete this tenant? This action cannot be undone.")
            .default(false)
            .interact()? 
        {
            println!("❌ Tenant deletion cancelled.");
            return Ok(());
        }
    }
    
    println!("🗑️  Deleting tenant...");
    
    match manager.delete_tenant(&tenant_id).await {
        Ok(_) => {
            println!("✅ Tenant deleted successfully!");
        }
        Err(e) => {
            return Err(color_eyre::eyre::eyre!("Failed to delete tenant: {}", e));
        }
    }
    
    Ok(())
}
