//! Fortress Authentication Plugins
//!
//! This crate provides WebAssembly-based authentication plugins for the Fortress
//! secure database system. Each plugin implements a specific authentication
//! method that can be hot-swapped and updated independently.

pub mod jwt_plugin;
pub mod oauth_plugin;
pub mod saml_plugin;

// Re-export plugin registry for easy access
pub struct PluginRegistry {
    plugins: std::collections::HashMap<String, PluginMetadata>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            plugins: std::collections::HashMap::new(),
        };
        
        // Register all available plugins
        let jwt_meta = jwt_plugin::get_metadata();
        registry.register_plugin("jwt", PluginMetadata {
            name: jwt_meta.name,
            version: jwt_meta.version,
            description: jwt_meta.description,
            author: jwt_meta.author,
            supported_methods: jwt_meta.supported_methods,
            required_config: jwt_meta.required_config,
            capabilities: PluginCapabilities {
                can_generate_tokens: jwt_meta.capabilities.can_generate_tokens,
                can_validate_tokens: jwt_meta.capabilities.can_validate_tokens,
                can_refresh_tokens: jwt_meta.capabilities.can_refresh_tokens,
                supports_mfa: jwt_meta.capabilities.supports_mfa,
                supports_rbac: jwt_meta.capabilities.supports_rbac,
            },
        });
        
        let oauth_meta = oauth_plugin::get_metadata();
        registry.register_plugin("oauth", PluginMetadata {
            name: oauth_meta.name,
            version: oauth_meta.version,
            description: oauth_meta.description,
            author: oauth_meta.author,
            supported_methods: oauth_meta.supported_methods,
            required_config: oauth_meta.required_config,
            capabilities: PluginCapabilities {
                can_generate_tokens: oauth_meta.capabilities.can_generate_tokens,
                can_validate_tokens: oauth_meta.capabilities.can_validate_tokens,
                can_refresh_tokens: oauth_meta.capabilities.can_refresh_tokens,
                supports_mfa: oauth_meta.capabilities.supports_mfa,
                supports_rbac: oauth_meta.capabilities.supports_rbac,
            },
        });
        
        let saml_meta = saml_plugin::get_metadata();
        registry.register_plugin("saml", PluginMetadata {
            name: saml_meta.name,
            version: saml_meta.version,
            description: saml_meta.description,
            author: saml_meta.author,
            supported_methods: saml_meta.supported_methods,
            required_config: saml_meta.required_config,
            capabilities: PluginCapabilities {
                can_generate_tokens: saml_meta.capabilities.can_generate_tokens,
                can_validate_tokens: saml_meta.capabilities.can_validate_tokens,
                can_refresh_tokens: saml_meta.capabilities.can_refresh_tokens,
                supports_mfa: saml_meta.capabilities.supports_mfa,
                supports_rbac: saml_meta.capabilities.supports_rbac,
            },
        });
        
        registry
    }
    
    fn register_plugin(&mut self, name: &str, metadata: PluginMetadata) {
        self.plugins.insert(name.to_string(), metadata);
    }
    
    pub fn get_plugin(&self, name: &str) -> Option<&PluginMetadata> {
        self.plugins.get(name)
    }
    
    pub fn list_plugins(&self) -> Vec<&str> {
        self.plugins.keys().map(|s| s.as_str()).collect()
    }
}

/// Common plugin metadata structure
#[derive(Debug, Clone)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub supported_methods: Vec<String>,
    pub required_config: Vec<String>,
    pub capabilities: PluginCapabilities,
}

#[derive(Debug, Clone)]
pub struct PluginCapabilities {
    pub can_generate_tokens: bool,
    pub can_validate_tokens: bool,
    pub can_refresh_tokens: bool,
    pub supports_mfa: bool,
    pub supports_rbac: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_plugin_registry() {
        let registry = PluginRegistry::new();
        
        // Test that all plugins are registered
        assert!(registry.get_plugin("jwt").is_some());
        assert!(registry.get_plugin("oauth").is_some());
        assert!(registry.get_plugin("saml").is_some());
        
        // Test plugin listing
        let plugins = registry.list_plugins();
        assert_eq!(plugins.len(), 3);
        assert!(plugins.contains(&"jwt"));
        assert!(plugins.contains(&"oauth"));
        assert!(plugins.contains(&"saml"));
    }
}
