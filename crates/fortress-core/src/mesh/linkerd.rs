//! Linkerd Service Mesh Integration
//! 
//! This module provides integration with Linkerd service mesh for traffic
//! management, security, and observability features.

use std::collections::HashMap;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use crate::error::{FortressError, Result};
use crate::mesh::{MeshProvider, MeshConfig, MeshNode, MeshNodeHealthStatus, TrafficPolicy, SecurityPolicy, MeshMetrics, MeshType};

/// Linkerd mesh provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerdMeshConfig {
    pub controller_api_address: String,
    pub proxy_api_address: String,
    pub namespace: String,
    pub service_discovery_enabled: bool,
    pub traffic_management_enabled: bool,
    pub security_enabled: bool,
    pub telemetry_enabled: bool,
    pub profile_enabled: bool,
}

impl Default for LinkerdMeshConfig {
    fn default() -> Self {
        Self {
            controller_api_address: "http://linkerd-controller.linkerd.svc.cluster.local:8085".to_string(),
            proxy_api_address: "http://localhost:4191".to_string(),
            namespace: "default".to_string(),
            service_discovery_enabled: true,
            traffic_management_enabled: true,
            security_enabled: true,
            telemetry_enabled: true,
            profile_enabled: true,
        }
    }
}

/// Linkerd mesh provider
pub struct LinkerdMesh {
    config: LinkerdMeshConfig,
    client: Option<reqwest::Client>,
    initialized: bool,
    node_cache: Arc<tokio::sync::RwLock<HashMap<String, MeshNode>>>,
    service_cache: Arc<tokio::sync::RwLock<HashMap<String, (DateTime<Utc>, LinkerdService)>>>,
}

impl LinkerdMesh {
    /// Create a new Linkerd mesh provider
    pub fn new(config: LinkerdMeshConfig) -> Self {
        Self {
            config,
            client: None,
            initialized: false,
            node_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            service_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Create HTTP client for Linkerd APIs
    fn create_client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    }

    /// Build Linkerd controller API URL
    fn build_controller_url(&self, endpoint: &str) -> String {
        let base_url = self.config.controller_api_address.trim_end_matches('/');
        format!("{}/{}", base_url, endpoint)
    }

    /// Build Linkerd proxy API URL
    fn build_proxy_url(&self, endpoint: &str) -> String {
        let base_url = self.config.proxy_api_address.trim_end_matches('/');
        format!("{}/{}", base_url, endpoint)
    }

    /// Get Linkerd services from controller API
    async fn get_linkerd_services(&self) -> Result<Vec<LinkerdService>> {
        let client = self.client.as_ref()
            .ok_or_else(|| FortressError::mesh("Linkerd client not initialized"))?;

        let url = self.build_controller_url("api/v1/services");
        
        let response = client.get(&url)
            .send()
            .await
            .map_err(|e| FortressError::mesh(format!("Linkerd services API request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(FortressError::mesh(format!("Linkerd services API returned status: {}", response.status())));
        }

        let services: Vec<LinkerdService> = response.json()
            .await
            .map_err(|e| FortressError::mesh(format!("Failed to parse Linkerd services response: {}", e)))?;

        Ok(services)
    }

    /// Get Linkerd HTTP routes
    async fn get_linkerd_http_routes(&self) -> Result<Vec<LinkerdHttpRoute>> {
        let client = self.client.as_ref()
            .ok_or_else(|| FortressError::mesh("Linkerd client not initialized"))?;

        let url = self.build_controller_url("api/v1/http-routes");
        
        let response = client.get(&url)
            .send()
            .await
            .map_err(|e| FortressError::mesh(format!("Linkerd HTTP routes API request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(FortressError::mesh(format!("Linkerd HTTP routes API returned status: {}", response.status())));
        }

        let routes: Vec<LinkerdHttpRoute> = response.json()
            .await
            .map_err(|e| FortressError::mesh(format!("Failed to parse Linkerd HTTP routes response: {}", e)))?;

        Ok(routes)
    }

    /// Get Linkerd server policies
    async fn get_linkerd_server_policies(&self) -> Result<Vec<LinkerdServerPolicy>> {
        let client = self.client.as_ref()
            .ok_or_else(|| FortressError::mesh("Linkerd client not initialized"))?;

        let url = self.build_controller_url("api/v1/server-policies");
        
        let response = client.get(&url)
            .send()
            .await
            .map_err(|e| FortressError::mesh(format!("Linkerd server policies API request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(FortressError::mesh(format!("Linkerd server policies API returned status: {}", response.status())));
        }

        let policies: Vec<LinkerdServerPolicy> = response.json()
            .await
            .map_err(|e| FortressError::mesh(format!("Failed to parse Linkerd server policies response: {}", e)))?;

        Ok(policies)
    }

    /// Get Linkerd authorization policies
    async fn get_linkerd_authz_policies(&self) -> Result<Vec<LinkerdAuthzPolicy>> {
        let client = self.client.as_ref()
            .ok_or_else(|| FortressError::mesh("Linkerd client not initialized"))?;

        let url = self.build_controller_url("api/v1/authorization-policies");
        
        let response = client.get(&url)
            .send()
            .await
            .map_err(|e| FortressError::mesh(format!("Linkerd authz policies API request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(FortressError::mesh(format!("Linkerd authz policies API returned status: {}", response.status())));
        }

        let policies: Vec<LinkerdAuthzPolicy> = response.json()
            .await
            .map_err(|e| FortressError::mesh(format!("Failed to parse Linkerd authz policies response: {}", e)))?;

        Ok(policies)
    }

    /// Convert Linkerd service to mesh node
    fn linkerd_service_to_mesh_node(&self, service: &LinkerdService) -> Result<MeshNode> {
        let node_id = format!("linkerd-service-{}", service.name);
        
        // Extract IP address from service endpoints
        let ip_address = service.endpoints.first()
            .and_then(|endpoint| endpoint.address.as_ref())
            .cloned()
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let port = service.endpoints.first()
            .map(|endpoint| endpoint.port)
            .unwrap_or(8080);

        // Create labels
        let mut labels = HashMap::new();
        labels.insert("mesh_provider".to_string(), "linkerd".to_string());
        labels.insert("service_name".to_string(), service.name.clone());
        labels.insert("service_type".to_string(), service.service_type.clone());
        
        for (key, value) in &service.labels {
            labels.insert(key.clone(), value.clone());
        }

        // Create metadata
        let mut metadata = HashMap::new();
        metadata.insert("service_name".to_string(), service.name.clone());
        metadata.insert("service_type".to_string(), service.service_type.clone());
        metadata.insert("namespace".to_string(), service.namespace.clone());
        metadata.insert("total_endpoints".to_string(), service.endpoints.len().to_string());

        // Determine health status
        let healthy_endpoints = service.endpoints.iter().filter(|e| e.healthy).count();
        let health_percentage = if service.endpoints.is_empty() {
            0
        } else {
            (healthy_endpoints * 100) / service.endpoints.len()
        };

        let health_status = if health_percentage >= 80 {
            MeshNodeHealthStatus::Healthy
        } else if health_percentage >= 50 {
            MeshNodeHealthStatus::Degraded
        } else if health_percentage > 0 {
            MeshNodeHealthStatus::Unhealthy
        } else {
            MeshNodeHealthStatus::Unknown
        };

        Ok(MeshNode {
            id: node_id,
            name: service.name.clone(),
            namespace: service.namespace.clone(),
            service_account: service.service_account.clone(),
            workload_name: service.name.clone(),
            labels,
            annotations: HashMap::new(),
            ip_address,
            port,
            mesh_type: MeshType::Linkerd,
            last_seen: Utc::now(),
            health_status,
        })
    }

    /// Convert Linkerd HTTP route to traffic policy
    fn linkerd_http_route_to_traffic_policy(&self, route: &LinkerdHttpRoute) -> Result<TrafficPolicy> {
        let mut rules = Vec::new();

        for rule in &route.spec.rules {
            let traffic_rule = TrafficRule {
                name: rule.name.clone(),
                priority: rule.priority.unwrap_or(100),
                match_conditions: rule.matches.iter().map(|m| crate::mesh::MatchCondition {
                    field: m.name.clone(),
                    operator: match m.regex {
                        true => crate::mesh::MatchOperator::Regex,
                        false => crate::mesh::MatchOperator::Equals,
                    },
                    value: m.value.clone(),
                }).collect(),
                actions: rule.route.iter().map(|r| crate::mesh::TrafficAction {
                    action_type: crate::mesh::ActionType::Route,
                    parameters: serde_json::json!({
                        "cluster": r.service_name.clone(),
                        "weight": r.weight.unwrap_or(100)
                    }),
                }).collect(),
                timeout_seconds: route.timeout.as_ref().map(|t| t.parse().unwrap_or(30)),
                retries: route.retries.as_ref().map(|r| r.attempts.parse().unwrap_or(3)),
            };
            rules.push(traffic_rule);
        }

        Ok(TrafficPolicy {
            name: route.metadata.name.clone(),
            namespace: route.metadata.namespace.clone(),
            selector: HashMap::new(), // Would need to extract from route metadata
            rules,
            created_at: route.metadata.creation_timestamp.unwrap_or_else(|| Utc::now()),
            updated_at: route.metadata.creation_timestamp.unwrap_or_else(|| Utc::now()),
        })
    }

    /// Convert Linkerd server policy to security policy
    fn linkerd_server_policy_to_security_policy(&self, policy: &LinkerdServerPolicy) -> Result<SecurityPolicy> {
        let mut auth_rules = Vec::new();
        let mut authz_rules = Vec::new();

        // Convert Linkerd server policy to our format
        if let Some(ref authn) = policy.spec.authentication {
            let auth_rule = crate::mesh::AuthRule {
                name: format!("{}-authn", policy.metadata.name),
                method: crate::mesh::AuthMethod::JWT, // Default to JWT
                jwt_rules: Some(crate::mesh::JwtRule {
                    issuer: "linkerd".to_string(),
                    audiences: vec![],
                    from_cookies: vec![],
                    from_headers: vec!["authorization".to_string()],
                    output_payload_to_header: "x-jwt-payload".to_string(),
                }),
                peer_auth_method: Some(crate::mesh::PeerAuthMethod::MTLS),
            };
            auth_rules.push(auth_rule);
        }

        if let Some(ref authz) = policy.spec.authorization {
            let authz_rule = crate::mesh::AuthzRule {
                name: format!("{}-authz", policy.metadata.name),
                action: crate::mesh::AuthzAction::Allow, // Default to allow
                when: authz.allow_unauthenticated.iter().map(|_| crate::mesh::AuthzCondition {
                    key: "authenticated".to_string(),
                    values: vec!["true".to_string()],
                    not_values: vec![],
                }).collect(),
                deny: false,
            };
            authz_rules.push(authz_rule);
        }

        Ok(SecurityPolicy {
            name: policy.metadata.name.clone(),
            namespace: policy.metadata.namespace.clone(),
            selector: policy.spec.selector.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            authentication_rules: auth_rules,
            authorization_rules: authz_rules,
            mtls_enabled: policy.spec.authentication.is_some(),
            created_at: policy.metadata.creation_timestamp.unwrap_or_else(|| Utc::now()),
            updated_at: policy.metadata.creation_timestamp.unwrap_or_else(|| Utc::now()),
        })
    }

    /// Apply traffic policy via Linkerd HTTP route
    async fn apply_linkerd_traffic_policy(&self, policy: &TrafficPolicy) -> Result<()> {
        // Convert traffic policy to Linkerd HTTP route
        let route = self.convert_traffic_policy_to_linkerd_http_route(policy)?;
        
        // Apply via Linkerd controller API
        self.apply_linkerd_http_route(&route).await
    }

    /// Apply security policy via Linkerd server policy
    async fn apply_linkerd_security_policy(&self, policy: &SecurityPolicy) -> Result<()> {
        // Convert security policy to Linkerd server policy
        let server_policy = self.convert_security_policy_to_linkerd_server_policy(policy)?;
        
        // Apply via Linkerd controller API
        self.apply_linkerd_server_policy(&server_policy).await
    }

    /// Convert traffic policy to Linkerd HTTP route
    fn convert_traffic_policy_to_linkerd_http_route(&self, policy: &TrafficPolicy) -> Result<LinkerdHttpRoute> {
        let mut route_rules = Vec::new();

        for rule in &policy.rules {
            let linkerd_rule = LinkerdHttpRouteRule {
                matches: rule.match_conditions.iter().map(|m| LinkerdHttpMatch {
                    name: m.field.clone(),
                    value: m.value.clone(),
                    regex: matches!(m.operator, crate::mesh::MatchOperator::Regex),
                }).collect(),
                route: rule.actions.iter().map(|a| {
                    if let crate::mesh::ActionType::Route = a.action_type {
                        LinkerdHttpRouteDestination {
                            service_name: a.parameters["cluster"].as_str().unwrap_or("fortress").to_string(),
                            weight: a.parameters["weight"].as_u64().unwrap_or(100) as u32,
                        }
                    } else {
                        LinkerdHttpRouteDestination {
                            service_name: "fortress".to_string(),
                            weight: 100,
                        }
                    }
                }).collect(),
                timeout: rule.timeout_seconds.map(|t| format!("{}s", t)),
                retries: rule.retries.map(|r| LinkerdRetry {
                    attempts: r,
                    timeout: Some("10s".to_string()),
                }),
            };
            route_rules.push(linkerd_rule);
        }

        Ok(LinkerdHttpRoute {
            metadata: LinkerdMetadata {
                name: policy.name.clone(),
                namespace: policy.namespace.clone(),
                creation_timestamp: Some(policy.created_at),
            },
            spec: LinkerdHttpRouteSpec {
                rules: route_rules,
            },
        })
    }

    /// Convert security policy to Linkerd server policy
    fn convert_security_policy_to_linkerd_server_policy(&self, policy: &SecurityPolicy) -> Result<LinkerdServerPolicy> {
        let mut server_authn = None;
        let mut server_authz = None;

        if !policy.authentication_rules.is_empty() {
            server_authn = Some(LinkerdServerAuthn {
                allow_unauthenticated: false,
            });
        }

        if !policy.authorization_rules.is_empty() {
            server_authz = Some(LinkerdServerAuthz {
                allow_unauthenticated: policy.authorization_rules.iter().any(|r| matches!(r.action, crate::mesh::AuthzAction::Allow)),
            });
        }

        Ok(LinkerdServerPolicy {
            metadata: LinkerdMetadata {
                name: policy.name.clone(),
                namespace: policy.namespace.clone(),
                creation_timestamp: Some(policy.created_at),
            },
            spec: LinkerdServerPolicySpec {
                selector: policy.selector.clone(),
                authentication: server_authn,
                authorization: server_authz,
            },
        })
    }

    /// Apply Linkerd HTTP route via controller API
    async fn apply_linkerd_http_route(&self, route: &LinkerdHttpRoute) -> Result<()> {
        let client = self.client.as_ref()
            .ok_or_else(|| FortressError::mesh("Linkerd client not initialized"))?;

        let url = self.build_controller_url("api/v1/http-routes");
        
        let route_json = serde_json::to_value(route)
            .map_err(|e| FortressError::mesh(format!("Failed to serialize HTTP route: {}", e)))?;

        let response = client.put(&url)
            .json(&route_json)
            .send()
            .await
            .map_err(|e| FortressError::mesh(format!("Linkerd HTTP route API request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(FortressError::mesh(format!("Linkerd HTTP route API returned status: {}", response.status())));
        }

        tracing::info!("Applied Linkerd HTTP route: {}", route.metadata.name);
        Ok(())
    }

    /// Apply Linkerd server policy via controller API
    async fn apply_linkerd_server_policy(&self, policy: &LinkerdServerPolicy) -> Result<()> {
        let client = self.client.as_ref()
            .ok_or_else(|| FortressError::mesh("Linkerd client not initialized"))?;

        let url = self.build_controller_url("api/v1/server-policies");
        
        let policy_json = serde_json::to_value(policy)
            .map_err(|e| FortressError::mesh(format!("Failed to serialize server policy: {}", e)))?;

        let response = client.put(&url)
            .json(&policy_json)
            .send()
            .await
            .map_err(|e| FortressError::mesh(format!("Linkerd server policy API request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(FortressError::mesh(format!("Linkerd server policy API returned status: {}", response.status())));
        }

        tracing::info!("Applied Linkerd server policy: {}", policy.metadata.name);
        Ok(())
    }

    /// Get Linkerd metrics
    async fn get_linkerd_metrics(&self) -> Result<LinkerdMetrics> {
        // Get metrics from Linkerd proxy
        let client = self.client.as_ref()
            .ok_or_else(|| FortressError::mesh("Linkerd client not initialized"))?;

        let url = self.build_proxy_url("metrics");
        
        let response = client.get(url)
            .send()
            .await
            .map_err(|e| FortressError::mesh(format!("Linkerd metrics API request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(FortressError::mesh(format!("Linkerd metrics API returned status: {}", response.status())));
        }

        let metrics_text = response.text()
            .await
            .map_err(|e| FortressError::mesh(format!("Failed to read Linkerd metrics response: {}", e)))?;

        self.parse_linkerd_metrics(&metrics_text)
    }

    /// Parse Linkerd metrics from text format
    fn parse_linkerd_metrics(&self, metrics_text: &str) -> Result<LinkerdMetrics> {
        let mut metrics = LinkerdMetrics::default();

        for line in metrics_text.lines() {
            if let Some((name, value)) = line.split_once(' ') {
                let name = name.trim();
                let value = value.trim();

                match name {
                    name if name.contains("request_total") => {
                        metrics.request_total += value.parse().unwrap_or(0);
                    }
                    name if name.contains("request_success_total") => {
                        metrics.request_success_total += value.parse().unwrap_or(0);
                    }
                    name if name.contains("request_failure_total") => {
                        metrics.request_failure_total += value.parse().unwrap_or(0);
                    }
                    name if name.contains("connection_total") => {
                        metrics.connection_total += value.parse().unwrap_or(0);
                    }
                    name if name.contains("connection_open") => {
                        metrics.connection_open += value.parse().unwrap_or(0);
                    }
                    _ => {}
                }
            }
        }

        metrics.last_updated = Utc::now();
        Ok(metrics)
    }
}

#[async_trait::async_trait]
impl MeshProvider for LinkerdMesh {
    fn name(&self) -> &str {
        "linkerd"
    }

    fn mesh_type(&self) -> MeshType {
        MeshType::Linkerd
    }

    async fn initialize(&mut self, config: &MeshConfig) -> Result<()> {
        // Extract Linkerd-specific config
        let linkerd_config: LinkerdMeshConfig = serde_json::from_value(
            serde_json::to_value(&config.settings).unwrap_or_default()
        ).unwrap_or_default();

        self.config = linkerd_config;

        // Create HTTP client
        self.client = Some(self.create_client());
        self.initialized = true;

        tracing::info!("Linkerd mesh provider initialized");
        Ok(())
    }

    async fn get_mesh_nodes(&self) -> Result<Vec<MeshNode>> {
        if !self.initialized {
            return Err(FortressError::mesh("Linkerd mesh provider not initialized"));
        }

        let mut nodes = Vec::new();

        // Get services and convert to mesh nodes
        match self.get_linkerd_services().await {
            Ok(services) => {
                for service in services {
                    match self.linkerd_service_to_mesh_node(&service) {
                        Ok(node) => nodes.push(node),
                        Err(e) => {
                            tracing::warn!("Failed to convert Linkerd service to mesh node: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to get Linkerd services: {}", e);
            }
        }

        tracing::debug!("Linkerd mesh found {} nodes", nodes.len());
        Ok(nodes)
    }

    async fn get_traffic_policies(&self) -> Result<Vec<TrafficPolicy>> {
        if !self.initialized {
            return Err(FortressError::mesh("Linkerd mesh provider not initialized"));
        }

        let mut policies = Vec::new();

        // Get HTTP routes and convert to traffic policies
        match self.get_linkerd_http_routes().await {
            Ok(routes) => {
                for route in routes {
                    match self.linkerd_http_route_to_traffic_policy(&route) {
                        Ok(policy) => policies.push(policy),
                        Err(e) => {
                            tracing::warn!("Failed to convert Linkerd HTTP route to traffic policy: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to get Linkerd HTTP routes: {}", e);
            }
        }

        Ok(policies)
    }

    async fn get_security_policies(&self) -> Result<Vec<SecurityPolicy>> {
        if !self.initialized {
            return Err(FortressError::mesh("Linkerd mesh provider not initialized"));
        }

        let mut policies = Vec::new();

        // Get server policies and convert to security policies
        match self.get_linkerd_server_policies().await {
            Ok(server_policies) => {
                for policy in server_policies {
                    match self.linkerd_server_policy_to_security_policy(&policy) {
                        Ok(security_policy) => policies.push(security_policy),
                        Err(e) => {
                            tracing::warn!("Failed to convert Linkerd server policy to security policy: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to get Linkerd server policies: {}", e);
            }
        }

        // Get authorization policies and convert to security policies
        match self.get_linkerd_authz_policies().await {
            Ok(authz_policies) => {
                for authz in authz_policies {
                    // Convert authz policy to security policy (implementation similar to server policy)
                    let security_policy = self.linkerd_authz_policy_to_security_policy(&authz)?;
                    policies.push(security_policy);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to get Linkerd authz policies: {}", e);
            }
        }

        Ok(policies)
    }

    async fn apply_traffic_policy(&self, policy: &TrafficPolicy) -> Result<()> {
        if !self.initialized {
            return Err(FortressError::mesh("Linkerd mesh provider not initialized"));
        }

        self.apply_linkerd_traffic_policy(policy).await
    }

    async fn apply_security_policy(&self, policy: &SecurityPolicy) -> Result<()> {
        if !self.initialized {
            return Err(FortressError::mesh("Linkerd mesh provider not initialized"));
        }

        self.apply_linkerd_security_policy(policy).await
    }

    async fn get_metrics(&self) -> Result<MeshMetrics> {
        if !self.initialized {
            return Err(FortressError::mesh("Linkerd mesh provider not initialized"));
        }

        let linkerd_metrics = self.get_linkerd_metrics().await?;
        
        Ok(MeshMetrics {
            request_count: linkerd_metrics.request_total,
            request_duration_ms: 0, // Would need to calculate from histogram stats
            request_error_count: linkerd_metrics.request_failure_total,
            request_success_rate: if linkerd_metrics.request_total > 0 {
                (linkerd_metrics.request_total - linkerd_metrics.request_failure_total) as f64 / linkerd_metrics.request_total as f64
            } else {
                0.0
            },
            connection_count: linkerd_metrics.connection_total,
            active_connections: linkerd_metrics.connection_open,
            last_updated: linkerd_metrics.last_updated,
        })
    }

    async fn check_mesh_health(&self) -> Result<MeshNodeHealthStatus> {
        if !self.initialized {
            return Err(FortressError::mesh("Linkerd mesh provider not initialized"));
        }

        // Check if Linkerd controller API is accessible
        let client = self.client.as_ref()
            .ok_or_else(|| FortressError::mesh("Linkerd client not initialized"));

        let url = self.build_controller_url("api/v1/services");
        
        match client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(MeshNodeHealthStatus::Healthy)
                } else {
                    Ok(MeshNodeHealthStatus::Unhealthy)
                }
            }
            Err(_) => Ok(MeshNodeHealthStatus::Unhealthy),
        }
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.client = None;
        self.initialized = false;
        
        // Clear caches
        {
            let mut node_cache = self.node_cache.write().await;
            node_cache.clear();
        }
        {
            let mut service_cache = self.service_cache.write().await;
            service_cache.clear();
        }
        
        tracing::info!("Linkerd mesh provider shutdown");
        Ok(())
    }

    /// Convert Linkerd authorization policy to security policy
    fn linkerd_authz_policy_to_security_policy(&self, authz: &LinkerdAuthzPolicy) -> Result<SecurityPolicy> {
        let mut authz_rules = Vec::new();

        // Convert Linkerd authz policy to our format
        let authz_rule = crate::mesh::AuthzRule {
            name: authz.metadata.name.clone(),
            action: crate::mesh::AuthzAction::Allow, // Default to allow
            when: authz.spec.allow_unauthenticated.iter().map(|_| crate::mesh::AuthzCondition {
                key: "authenticated".to_string(),
                values: vec!["true".to_string()],
                not_values: vec![],
            }).collect(),
            deny: !authz.spec.allow_unauthenticated,
        };
        authz_rules.push(authz_rule);

        Ok(SecurityPolicy {
            name: authz.metadata.name.clone(),
            namespace: authz.metadata.namespace.clone(),
            selector: authz.spec.selector.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            authentication_rules: Vec::new(), // Auth handled in server policy
            authorization_rules: authz_rules,
            mtls_enabled: true, // Linkerd uses mTLS by default
            created_at: authz.metadata.creation_timestamp.unwrap_or_else(|| Utc::now()),
            updated_at: authz.metadata.creation_timestamp.unwrap_or_else(|| Utc::now()),
        })
    }
}

// Linkerd data structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerdService {
    pub name: String,
    pub namespace: String,
    pub service_type: String,
    pub service_account: String,
    pub labels: HashMap<String, String>,
    pub endpoints: Vec<LinkerdEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerdEndpoint {
    pub address: Option<String>,
    pub port: u16,
    pub healthy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerdHttpRoute {
    pub metadata: LinkerdMetadata,
    pub spec: LinkerdHttpRouteSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerdMetadata {
    pub name: String,
    pub namespace: String,
    pub creation_timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerdHttpRouteSpec {
    pub rules: Vec<LinkerdHttpRouteRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerdHttpRouteRule {
    pub name: Option<String>,
    pub priority: Option<u32>,
    pub matches: Vec<LinkerdHttpMatch>,
    pub route: Vec<LinkerdHttpRouteDestination>,
    pub timeout: Option<String>,
    pub retries: Option<LinkerdRetry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerdHttpMatch {
    pub name: String,
    pub value: String,
    pub regex: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerdHttpRouteDestination {
    pub service_name: String,
    pub weight: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerdRetry {
    pub attempts: u32,
    pub timeout: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerdServerPolicy {
    pub metadata: LinkerdMetadata,
    pub spec: LinkerdServerPolicySpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerdServerPolicySpec {
    pub selector: HashMap<String, String>,
    pub authentication: Option<LinkerdServerAuthn>,
    pub authorization: Option<LinkerdServerAuthz>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerdServerAuthn {
    pub allow_unauthenticated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerdServerAuthz {
    pub allow_unauthenticated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerdAuthzPolicy {
    pub metadata: LinkerdMetadata,
    pub spec: LinkerdAuthzPolicySpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkerdAuthzPolicySpec {
    pub selector: HashMap<String, String>,
    pub allow_unauthenticated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct LinkerdMetrics {
    pub request_total: u64,
    pub request_success_total: u64,
    pub request_failure_total: u64,
    pub connection_total: u64,
    pub connection_open: u64,
    pub last_updated: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linkerd_config_default() {
        let config = LinkerdMeshConfig::default();
        assert_eq!(config.controller_api_address, "http://linkerd-controller.linkerd.svc.cluster.local:8085");
        assert_eq!(config.proxy_api_address, "http://localhost:4191");
        assert_eq!(config.namespace, "default");
        assert!(config.service_discovery_enabled);
        assert!(config.traffic_management_enabled);
        assert!(config.security_enabled);
    }

    #[test]
    fn test_linkerd_mesh_creation() {
        let config = LinkerdMeshConfig::default();
        let mesh = LinkerdMesh::new(config);
        
        assert_eq!(mesh.name(), "linkerd");
        assert_eq!(mesh.mesh_type(), MeshType::Linkerd);
        assert!(!mesh.initialized);
        assert!(mesh.client.is_none());
    }
}
