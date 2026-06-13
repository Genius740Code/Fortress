//! DNS Discovery Provider
//!
//! This module provides automatic discovery of Fortress cluster nodes
//! through DNS SRV records and A/AAAA records.

use crate::discovery::{DiscoveredNode, DiscoveryConfig, DiscoveryProvider, NodeHealthStatus};
use crate::error::{FortressError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// DNS discovery provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsDiscoveryConfig {
    pub service_name: String,
    pub domain: String,
    pub record_type: DnsRecordType,
    pub port: Option<u16>,
    pub resolver_servers: Vec<String>,
    pub timeout_seconds: u64,
    pub retry_attempts: u32,
    pub health_check_enabled: bool,
    pub health_check_path: Option<String>,
    pub health_check_interval_seconds: u64,
}

/// DNS record types for discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsRecordType {
    SRV,
    A,
    AAAA,
    TXT,
}

impl Default for DnsDiscoveryConfig {
    fn default() -> Self {
        Self {
            service_name: "fortress".to_string(),
            domain: "example.com".to_string(),
            record_type: DnsRecordType::SRV,
            port: Some(8080),
            resolver_servers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
            timeout_seconds: 5,
            retry_attempts: 3,
            health_check_enabled: true,
            health_check_path: Some("/health".to_string()),
            health_check_interval_seconds: 30,
        }
    }
}

/// DNS discovery provider
pub struct DnsDiscovery {
    config: DnsDiscoveryConfig,
    resolver: Option<trust_dns_resolver::TokioAsyncResolver>,
    initialized: bool,
    node_cache: Arc<RwLock<HashMap<String, DiscoveredNode>>>,
}

impl DnsDiscovery {
    /// Create a new DNS discovery provider
    pub fn new(config: DnsDiscoveryConfig) -> Self {
        Self {
            config,
            resolver: None,
            initialized: false,
            node_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create DNS resolver
    fn create_resolver(&self) -> Result<Option<trust_dns_resolver::TokioAsyncResolver>> {
        let mut resolver_config = trust_dns_resolver::config::ResolverConfig::new();

        // Add custom DNS servers if provided
        for server in &self.config.dns_servers {
            resolver_config.add_name_server(trust_dns_resolver::config::NameServerConfig {
                socket_addr: *server,
                protocol: trust_dns_resolver::config::Protocol::Udp,
                tls_config: None,
                trust_nx_responses: false,
                bind_addr: None,
            });
        }

        let resolver_opts = trust_dns_resolver::config::ResolverOpts::default();

        match (resolver_config, resolver_opts).into() {
            Ok(resolver) => Ok(Some(resolver)),
            Err(e) => {
                tracing::warn!("Failed to create DNS resolver: {}", e);
                Ok(None)
            }
        }
    }

    /// Resolve SRV records
    async fn resolve_srv_records(&self) -> Result<Vec<trust_dns_resolver::proto::rr::rdata::SRV>> {
        let resolver = match &self.resolver {
            Some(resolver) => resolver,
            None => return Ok(Vec::new()),
        };

        let srv_name = format!("_{}._tcp.{}", self.config.service_name, self.config.domain);

        let name = trust_dns_resolver::proto::rr::Name::from_ascii(srv_name.as_bytes())
            .map_err(|e| FortressError::discovery(format!("Invalid SRV name: {}", e)))?;

        match resolver.srv_lookup(name).await {
            Ok(lookup_result) => Ok(lookup_result.iter().cloned().collect()),
            Err(e) => {
                tracing::warn!("SRV lookup failed: {}", e);
                Ok(Vec::new())
            }
        }
    }

    /// Resolve A records
    async fn resolve_a_records(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        let resolver = match &self.resolver {
            Some(resolver) => resolver,
            None => return Ok(Vec::new()),
        };

        let name = trust_dns_resolver::proto::rr::Name::from_ascii(hostname.as_bytes())
            .map_err(|e| FortressError::discovery(format!("Invalid hostname: {}", e)))?;

        match resolver.ipv4_lookup(name).await {
            Ok(response) => Ok(response.iter().map(|addr| IpAddr::V4(*addr)).collect()),
            Err(e) => {
                tracing::warn!("A record lookup failed: {}", e);
                Ok(Vec::new())
            }
        }
    }

    /// Resolve AAAA records
    async fn resolve_aaaa_records(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        let resolver = match &self.resolver {
            Some(resolver) => resolver,
            None => return Ok(Vec::new()),
        };

        let name = trust_dns_resolver::proto::rr::Name::from_ascii(hostname.as_bytes())
            .map_err(|e| FortressError::discovery(format!("Invalid hostname: {}", e)))?;

        match resolver.ipv6_lookup(name).await {
            Ok(response) => Ok(response.iter().map(|addr| IpAddr::V6(*addr)).collect()),
            Err(e) => {
                tracing::warn!("AAAA record lookup failed: {}", e);
                Ok(Vec::new())
            }
        }
    }

    /// Resolve TXT records
    async fn resolve_txt_records(&self, hostname: &str) -> Result<Vec<String>> {
        let resolver = match &self.resolver {
            Some(resolver) => resolver,
            None => return Ok(Vec::new()),
        };

        let name = trust_dns_resolver::proto::rr::Name::from_ascii(hostname.as_bytes())
            .map_err(|e| FortressError::discovery(format!("Invalid hostname: {}", e)))?;

        match resolver.txt_lookup(name).await {
            Ok(response) => {
                let mut txt_records = Vec::new();
                for txt in response.iter() {
                    let txt_string = String::from_utf8_lossy(&txt.data);
                    txt_records.push(txt_string.to_string());
                }
                Ok(txt_records)
            }
            Err(e) => {
                tracing::warn!("TXT record lookup failed: {}", e);
                Ok(Vec::new())
            }
        }
    }

    /// Convert SRV record to discovered node
    fn srv_record_to_node(
        &self,
        srv: &trust_dns_resolver::proto::rr::rdata::SRV,
    ) -> Result<DiscoveredNode> {
        let hostname = srv.target().to_string();
        let port = srv.port() as u16;

        // Extract metadata from SRV record
        let mut metadata = HashMap::new();
        metadata.insert("priority".to_string(), srv.priority().to_string());
        metadata.insert("weight".to_string(), srv.weight().to_string());
        metadata.insert("hostname".to_string(), hostname.clone());
        metadata.insert("ttl".to_string(), srv.ttl().to_string());

        // Create tags
        let mut tags = HashMap::new();
        tags.insert("discovery_type".to_string(), "srv".to_string());
        tags.insert("service".to_string(), self.config.service_name.clone());

        Ok(DiscoveredNode {
            id: format!("dns-srv-{}", hostname.replace('.', "-")),
            address: hostname,
            port,
            region: None,
            zone: None,
            tags,
            metadata,
            last_seen: Utc::now(),
            health_status: NodeHealthStatus::Unknown,
            capabilities: vec!["dns_discovered".to_string()],
        })
    }

    /// Convert A/AAAA record to discovered node
    fn ip_record_to_node(&self, ip: IpAddr, hostname: Option<&str>) -> Result<DiscoveredNode> {
        let address = ip.to_string();
        let port = self.config.port.unwrap_or(8080);

        // Create metadata
        let mut metadata = HashMap::new();
        metadata.insert("ip_address".to_string(), address.clone());
        metadata.insert(
            "ip_type".to_string(),
            match ip {
                IpAddr::V4(_) => "ipv4".to_string(),
                IpAddr::V6(_) => "ipv6".to_string(),
            },
        );

        if let Some(host) = hostname {
            metadata.insert("hostname".to_string(), host.to_string());
        }

        // Create tags
        let mut tags = HashMap::new();
        tags.insert("discovery_type".to_string(), "ip".to_string());
        tags.insert("service".to_string(), self.config.service_name.clone());

        Ok(DiscoveredNode {
            id: format!("dns-ip-{}", address.replace(':', "-").replace('.', "-")),
            address,
            port,
            region: None,
            zone: None,
            tags,
            metadata,
            last_seen: Utc::now(),
            health_status: NodeHealthStatus::Unknown,
            capabilities: vec!["dns_discovered".to_string()],
        })
    }

    /// Parse TXT record metadata
    fn parse_txt_metadata(&self, txt_records: &[String]) -> HashMap<String, String> {
        let mut metadata = HashMap::new();

        for txt in txt_records {
            // Parse key=value pairs from TXT records
            for part in txt.split_whitespace() {
                if let Some((key, value)) = part.split_once('=') {
                    metadata.insert(key.to_string(), value.to_string());
                } else {
                    metadata.insert(part.to_string(), "true".to_string());
                }
            }
        }

        metadata
    }

    /// Perform health check on a node
    async fn perform_health_check(&self, node: &DiscoveredNode) -> Result<NodeHealthStatus> {
        if !self.config.health_check_enabled {
            return Ok(NodeHealthStatus::Unknown);
        }

        let health_check_path = self
            .config
            .health_check_path
            .as_deref()
            .unwrap_or("/health");
        let url = format!("http://{}:{}{}", node.address, node.port, health_check_path);

        // Check if we should perform health check (rate limiting)
        let node_id = &node.id;
        {
            let last_checks = self.last_health_check.read().await;
            if let Some(last_check) = last_checks.get(node_id) {
                let elapsed = Utc::now() - *last_check;
                if elapsed.num_seconds() < self.config.health_check_interval_seconds as i64 {
                    return Ok(NodeHealthStatus::Unknown); // Skip this check
                }
            }
        }

        // Update last health check time
        {
            let mut last_checks = self.last_health_check.write().await;
            last_checks.insert(node_id.clone(), Utc::now());
        }

        // Perform HTTP health check
        let client = reqwest::Client::new();
        let timeout = Duration::from_secs(self.config.timeout_seconds);

        match client.get(&url).timeout(timeout).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(NodeHealthStatus::Healthy)
                } else if response.status().is_server_error() {
                    Ok(NodeHealthStatus::Unhealthy)
                } else {
                    Ok(NodeHealthStatus::Degraded)
                }
            }
            Err(e) => {
                tracing::debug!("Health check failed for {}: {}", node.id, e);
                Ok(NodeHealthStatus::Unhealthy)
            }
        }
    }
}

#[async_trait::async_trait]
impl DiscoveryProvider for DnsDiscovery {
    fn name(&self) -> &str {
        "dns"
    }

    async fn initialize(&mut self, config: &DiscoveryConfig) -> Result<()> {
        // Extract DNS-specific config
        let dns_config: DnsDiscoveryConfig =
            serde_json::from_value(serde_json::to_value(&config.settings).unwrap_or_default())
                .unwrap_or_default();

        self.config = dns_config;

        // Create DNS resolver
        self.resolver = self.create_resolver().await?;
        self.initialized = true;

        tracing::info!(
            "DNS discovery provider initialized for service: {}.{}",
            self.config.service_name,
            self.config.domain
        );
        Ok(())
    }

    async fn discover_nodes(&self) -> Result<Vec<DiscoveredNode>> {
        if !self.initialized {
            return Err(FortressError::discovery(
                "DNS discovery provider not initialized",
            ));
        }

        let mut nodes = Vec::new();

        match self.config.record_type {
            DnsRecordType::SRV => {
                match self.resolve_srv_records().await {
                    Ok(srv_records) => {
                        for srv in srv_records {
                            match self.srv_record_to_node(&srv) {
                                Ok(mut node) => {
                                    // Try to resolve the hostname to get IP addresses
                                    let hostname = srv.target().to_string().trim_end_matches('.');
                                    if let Ok(ip_addresses) = self.resolve_a_records(hostname).await
                                    {
                                        if !ip_addresses.is_empty() {
                                            node.address = ip_addresses[0].to_string();
                                        }
                                    }
                                    nodes.push(node);
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to convert SRV record to node: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to resolve SRV records: {}", e);
                    }
                }
            }
            DnsRecordType::A => {
                let hostname = format!("{}.{}", self.config.service_name, self.config.domain);
                match self.resolve_a_records(&hostname).await {
                    Ok(ip_addresses) => {
                        for ip in ip_addresses {
                            match self.ip_record_to_node(ip, Some(&hostname)) {
                                Ok(node) => nodes.push(node),
                                Err(e) => {
                                    tracing::warn!("Failed to convert A record to node: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to resolve A records: {}", e);
                    }
                }
            }
            DnsRecordType::AAAA => {
                let hostname = format!("{}.{}", self.config.service_name, self.config.domain);
                match self.resolve_aaaa_records(&hostname).await {
                    Ok(ip_addresses) => {
                        for ip in ip_addresses {
                            match self.ip_record_to_node(ip, Some(&hostname)) {
                                Ok(node) => nodes.push(node),
                                Err(e) => {
                                    tracing::warn!("Failed to convert AAAA record to node: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to resolve AAAA records: {}", e);
                    }
                }
            }
            DnsRecordType::TXT => {
                let hostname = format!("{}.{}", self.config.service_name, self.config.domain);
                match self.resolve_txt_records(&hostname).await {
                    Ok(txt_records) => {
                        let metadata = self.parse_txt_metadata(&txt_records);

                        // TXT records typically contain metadata, not node addresses
                        // So we'll create a metadata node
                        let node = DiscoveredNode {
                            id: "dns-metadata".to_string(),
                            address: "metadata".to_string(),
                            port: 0,
                            region: None,
                            zone: None,
                            tags: HashMap::new(),
                            metadata,
                            last_seen: Utc::now(),
                            health_status: NodeHealthStatus::Unknown,
                            capabilities: vec!["metadata_provider".to_string()],
                        };
                        nodes.push(node);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to resolve TXT records: {}", e);
                    }
                }
            }
        }

        tracing::debug!("DNS discovery found {} nodes", nodes.len());
        Ok(nodes)
    }

    async fn check_node_health(&self, node: &DiscoveredNode) -> Result<NodeHealthStatus> {
        if !self.initialized {
            return Err(FortressError::discovery(
                "DNS discovery provider not initialized",
            ));
        }

        // Perform health check if enabled
        self.perform_health_check(node).await
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.resolver = None;
        self.initialized = false;
        tracing::info!("DNS discovery provider shutdown");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_config_default() {
        let config = DnsDiscoveryConfig::default();
        assert_eq!(config.service_name, "fortress");
        assert_eq!(config.domain, "example.com");
        assert!(matches!(config.record_type, DnsRecordType::SRV));
        assert_eq!(config.port, Some(8080));
        assert_eq!(config.timeout_seconds, 5);
        assert_eq!(config.retry_attempts, 3);
        assert!(config.health_check_enabled);
    }

    #[test]
    fn test_dns_discovery_creation() {
        let config = DnsDiscoveryConfig::default();
        let discovery = DnsDiscovery::new(config);

        assert_eq!(discovery.name(), "dns");
        assert!(!discovery.initialized);
        assert!(discovery.resolver.is_none());
    }

    #[test]
    fn test_parse_txt_metadata() {
        let config = DnsDiscoveryConfig::default();
        let discovery = DnsDiscovery::new(config);

        let txt_records = vec![
            "region=us-west-2".to_string(),
            "zone=us-west-2a".to_string(),
            "environment=production".to_string(),
        ];

        let metadata = discovery.parse_txt_metadata(&txt_records);

        assert_eq!(metadata.get("region"), Some(&"us-west-2".to_string()));
        assert_eq!(metadata.get("zone"), Some(&"us-west-2a".to_string()));
        assert_eq!(metadata.get("environment"), Some(&"production".to_string()));
    }
}
