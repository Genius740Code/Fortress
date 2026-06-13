//! Istio Service Mesh Integration
//!
//! This module provides integration with Istio service mesh for advanced
//! traffic management, security, and observability features.

use crate::error::{FortressError, Result};
use crate::mesh::{
    MeshConfig, MeshMetrics, MeshNode, MeshNodeHealthStatus, MeshProvider, MeshType,
    SecurityPolicy, TrafficAction, TrafficPolicy, TrafficRule,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Istio mesh provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioMeshConfig {
    pub pilot_address: String,
    pub galley_address: String,
    pub citadel_address: String,
    pub namespace: String,
    pub service_discovery_enabled: bool,
    pub traffic_management_enabled: bool,
    pub security_enabled: bool,
    pub telemetry_enabled: bool,
    pub config_map_name: String,
}

impl Default for IstioMeshConfig {
    fn default() -> Self {
        Self {
            pilot_address: "http://istio-pilot.istio-system:15014".to_string(),
            galley_address: "http://istio-galley.istio-system:9443".to_string(),
            citadel_address: "http://istio-citadel.istio-system:8080".to_string(),
            namespace: "default".to_string(),
            service_discovery_enabled: true,
            traffic_management_enabled: true,
            security_enabled: true,
            telemetry_enabled: true,
            config_map_name: "istio".to_string(),
        }
    }
}

/// Istio mesh provider
pub struct IstioMesh {
    config: IstioMeshConfig,
    client: Option<reqwest::Client>,
    initialized: bool,
    node_cache: Arc<tokio::sync::RwLock<HashMap<String, MeshNode>>>,
    service_cache: Arc<tokio::sync::RwLock<HashMap<String, (DateTime<Utc>, IstioService)>>>,
}

impl IstioMesh {
    /// Create a new Istio mesh provider
    pub fn new(config: IstioMeshConfig) -> Self {
        Self {
            config,
            client: None,
            initialized: false,
            node_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            service_cache: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Create HTTP client for Istio APIs
    fn create_client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    }

    /// Get Istio services from Pilot API
    async fn get_istio_services(&self) -> Result<Vec<IstioService>> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| FortressError::mesh("Istio client not initialized"))?;

        let url = format!("{}/v1/registration", self.config.pilot_address);

        let response =
            client.get(&url).send().await.map_err(|e| {
                FortressError::mesh(format!("Istio Pilot API request failed: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(FortressError::mesh(format!(
                "Istio Pilot API returned status: {}",
                response.status()
            )));
        }

        let services: Vec<IstioService> = response.json().await.map_err(|e| {
            FortressError::mesh(format!("Failed to parse Istio services response: {}", e))
        })?;

        Ok(services)
    }

    /// Get Istio virtual services
    async fn get_istio_virtual_services(&self) -> Result<Vec<IstioVirtualService>> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| FortressError::mesh("Istio client not initialized"))?;

        // Get virtual services from Kubernetes API
        let url = format!(
            "http://localhost:8080/apis/networking.istio.io/v1beta1/virtualservices?namespace={}",
            self.config.namespace
        );

        let response = client.get(&url).send().await.map_err(|e| {
            FortressError::mesh(format!("Istio VirtualService API request failed: {}", e))
        })?;

        if !response.status().is_success() {
            return Err(FortressError::mesh(format!(
                "Istio VirtualService API returned status: {}",
                response.status()
            )));
        }

        #[derive(Deserialize)]
        struct VirtualServiceList {
            items: Vec<IstioVirtualService>,
        }

        let vsvc_list: VirtualServiceList = response.json().await.map_err(|e| {
            FortressError::mesh(format!(
                "Failed to parse Istio VirtualService response: {}",
                e
            ))
        })?;

        Ok(vsvc_list.items)
    }

    /// Get Istio destination rules
    async fn get_istio_destination_rules(&self) -> Result<Vec<IstioDestinationRule>> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| FortressError::mesh("Istio client not initialized"))?;

        let url = format!(
            "http://localhost:8080/apis/networking.istio.io/v1beta1/destinationrules?namespace={}",
            self.config.namespace
        );

        let response = client.get(&url).send().await.map_err(|e| {
            FortressError::mesh(format!("Istio DestinationRule API request failed: {}", e))
        })?;

        if !response.status().is_success() {
            return Err(FortressError::mesh(format!(
                "Istio DestinationRule API returned status: {}",
                response.status()
            )));
        }

        #[derive(Deserialize)]
        struct DestinationRuleList {
            items: Vec<IstioDestinationRule>,
        }

        let dr_list: DestinationRuleList = response.json().await.map_err(|e| {
            FortressError::mesh(format!(
                "Failed to parse Istio DestinationRule response: {}",
                e
            ))
        })?;

        Ok(dr_list.items)
    }

    /// Get Istio authorization policies
    async fn get_istio_authz_policies(&self) -> Result<Vec<IstioAuthzPolicy>> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| FortressError::mesh("Istio client not initialized"))?;

        let url = format!("http://localhost:8080/apis/security.istio.io/v1beta1/authorizationpolicies?namespace={}", self.config.namespace);

        let response = client.get(&url).send().await.map_err(|e| {
            FortressError::mesh(format!("Istio AuthzPolicy API request failed: {}", e))
        })?;

        if !response.status().is_success() {
            return Err(FortressError::mesh(format!(
                "Istio AuthzPolicy API returned status: {}",
                response.status()
            )));
        }

        #[derive(Deserialize)]
        struct AuthzPolicyList {
            items: Vec<IstioAuthzPolicy>,
        }

        let authz_list: AuthzPolicyList = response.json().await.map_err(|e| {
            FortressError::mesh(format!("Failed to parse Istio AuthzPolicy response: {}", e))
        })?;

        Ok(authz_list.items)
    }

    /// Convert Istio service to mesh node
    fn istio_service_to_mesh_node(&self, service: &IstioService) -> Result<MeshNode> {
        let node_id = format!("istio-service-{}", service.name);

        // Extract IP address from service endpoints
        let ip_address = service
            .endpoints
            .first()
            .and_then(|endpoint| endpoint.address.as_ref())
            .cloned()
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let port = service
            .endpoints
            .first()
            .map(|endpoint| endpoint.port)
            .unwrap_or(8080);

        // Create labels
        let mut labels = HashMap::new();
        labels.insert("mesh_provider".to_string(), "istio".to_string());
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
        metadata.insert(
            "total_endpoints".to_string(),
            service.endpoints.len().to_string(),
        );

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
            mesh_type: MeshType::Istio,
            last_seen: Utc::now(),
            health_status,
        })
    }

    /// Convert Istio virtual service to traffic policy
    fn istio_virtual_service_to_traffic_policy(
        &self,
        vsvc: &IstioVirtualService,
    ) -> Result<TrafficPolicy> {
        let mut rules = Vec::new();

        for http_route in &vsvc.spec.http {
            for route in &http_route.route {
                let rule = TrafficRule {
                    name: format!(
                        "{}-{}",
                        vsvc.metadata.name,
                        route.destination.subset.clone().unwrap_or_default()
                    ),
                    priority: route.weight.unwrap_or(100) as u32,
                    match_conditions: Vec::new(), // Would need to parse match conditions
                    actions: vec![TrafficAction {
                        action_type: crate::mesh::ActionType::Route,
                        parameters: serde_json::json!({
                            "cluster": route.destination.subset.clone().unwrap_or_default(),
                            "host": route.destination.host.clone(),
                            "port": route.destination.port.unwrap_or(80),
                            "weight": route.weight.unwrap_or(100)
                        }),
                    }],
                    timeout_seconds: http_route.timeout.as_ref().map(|t| t.parse().unwrap_or(30)),
                    retries: http_route
                        .retries
                        .as_ref()
                        .map(|r| r.attempts.parse().unwrap_or(3)),
                };
                rules.push(rule);
            }
        }

        Ok(TrafficPolicy {
            name: vsvc.metadata.name.clone(),
            namespace: vsvc.metadata.namespace.clone(),
            selector: vsvc
                .spec
                .hosts
                .iter()
                .map(|h| ("host".to_string(), h.clone()))
                .collect(),
            rules,
            created_at: vsvc
                .metadata
                .creation_timestamp
                .unwrap_or_else(|| Utc::now()),
            updated_at: vsvc
                .metadata
                .creation_timestamp
                .unwrap_or_else(|| Utc::now()),
        })
    }

    /// Convert Istio authorization policy to security policy
    fn istio_authz_policy_to_security_policy(
        &self,
        authz: &IstioAuthzPolicy,
    ) -> Result<SecurityPolicy> {
        let mut auth_rules = Vec::new();
        let mut authz_rules = Vec::new();

        // Convert Istio authz rules to our format
        for rule in &authz.spec.rules {
            let auth_rule = crate::mesh::AuthRule {
                name: format!(
                    "{}-{}",
                    authz.metadata.name,
                    rule.name.clone().unwrap_or_default()
                ),
                method: crate::mesh::AuthMethod::JWT, // Default to JWT
                jwt_rules: Some(crate::mesh::JwtRule {
                    issuer: "istio".to_string(),
                    audiences: vec![],
                    from_cookies: vec![],
                    from_headers: vec!["authorization".to_string()],
                    output_payload_to_header: "x-jwt-payload".to_string(),
                }),
                peer_auth_method: Some(crate::mesh::PeerAuthMethod::MTLS),
            };
            auth_rules.push(auth_rule);

            let authz_rule = crate::mesh::AuthzRule {
                name: rule.name.clone().unwrap_or_default(),
                action: if rule.action.as_ref().map(|a| a.allow).unwrap_or(true) {
                    crate::mesh::AuthzAction::Allow
                } else {
                    crate::mesh::AuthzAction::Deny
                },
                when: rule
                    .when
                    .as_ref()
                    .map(|w| {
                        w.iter()
                            .map(|condition| crate::mesh::AuthzCondition {
                                key: condition.key.clone(),
                                values: condition.values.clone().unwrap_or_default(),
                                not_values: condition.not_values.clone().unwrap_or_default(),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                deny: !rule.action.as_ref().map(|a| a.allow).unwrap_or(true),
            };
            authz_rules.push(authz_rule);
        }

        Ok(SecurityPolicy {
            name: authz.metadata.name.clone(),
            namespace: authz.metadata.namespace.clone(),
            selector: authz
                .spec
                .selector
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            authentication_rules: auth_rules,
            authorization_rules: authz_rules,
            mtls_enabled: authz.spec.action.as_ref().map(|a| a.allow).unwrap_or(true),
            created_at: authz
                .metadata
                .creation_timestamp
                .unwrap_or_else(|| Utc::now()),
            updated_at: authz
                .metadata
                .creation_timestamp
                .unwrap_or_else(|| Utc::now()),
        })
    }

    /// Apply traffic policy via Istio VirtualService
    async fn apply_istio_traffic_policy(&self, policy: &TrafficPolicy) -> Result<()> {
        // Convert traffic policy to Istio VirtualService
        let vsvc = self.convert_traffic_policy_to_istio_virtual_service(policy)?;

        // Apply via Kubernetes API
        self.apply_istio_virtual_service(&vsvc).await
    }

    /// Apply security policy via Istio AuthorizationPolicy
    async fn apply_istio_security_policy(&self, policy: &SecurityPolicy) -> Result<()> {
        // Convert security policy to Istio AuthorizationPolicy
        let authz = self.convert_security_policy_to_istio_authz_policy(policy)?;

        // Apply via Kubernetes API
        self.apply_istio_authz_policy(&authz).await
    }

    /// Convert traffic policy to Istio VirtualService
    fn convert_traffic_policy_to_istio_virtual_service(
        &self,
        policy: &TrafficPolicy,
    ) -> Result<IstioVirtualService> {
        let mut http_routes = Vec::new();

        for rule in &policy.rules {
            let http_route = IstioHttpRoute {
                r#match: Vec::new(), // Would need to convert match conditions
                route: vec![IstioRouteDestination {
                    destination: IstioDestination {
                        host: "fortress.default.svc.cluster.local".to_string(),
                        subset: Some("v1".to_string()),
                        port: Some(8080),
                    },
                    weight: Some(100),
                }],
                timeout: rule.timeout_seconds.map(|t| format!("{}s", t)),
                retries: rule.retries.map(|r| IstioRetry {
                    attempts: r,
                    per_try_timeout: Some("10s".to_string()),
                    retry_on: Some(
                        "5xx,gateway-error,reset,connect-failure,refused-stream".to_string(),
                    ),
                }),
            };
            http_routes.push(http_route);
        }

        Ok(IstioVirtualService {
            metadata: IstioMetadata {
                name: policy.name.clone(),
                namespace: policy.namespace.clone(),
                creation_timestamp: Some(policy.created_at),
            },
            spec: IstioVirtualServiceSpec {
                hosts: vec!["fortress".to_string()],
                gateways: vec!["fortress-gateway".to_string()],
                http: http_routes,
            },
        })
    }

    /// Convert security policy to Istio AuthorizationPolicy
    fn convert_security_policy_to_istio_authz_policy(
        &self,
        policy: &SecurityPolicy,
    ) -> Result<IstioAuthzPolicy> {
        let mut rules = Vec::new();

        for authz_rule in &policy.authorization_rules {
            let rule = IstioAuthzPolicyRule {
                name: Some(authz_rule.name.clone()),
                when: authz_rule
                    .when
                    .iter()
                    .map(|condition| IstioAuthzCondition {
                        key: condition.key.clone(),
                        values: Some(condition.values.clone()),
                        not_values: Some(condition.not_values.clone()),
                    })
                    .collect(),
                action: Some(IstioAuthzAction {
                    allow: matches!(authz_rule.action, crate::mesh::AuthzAction::Allow),
                }),
            };
            rules.push(rule);
        }

        Ok(IstioAuthzPolicy {
            metadata: IstioMetadata {
                name: policy.name.clone(),
                namespace: policy.namespace.clone(),
                creation_timestamp: Some(policy.created_at),
            },
            spec: IstioAuthzPolicySpec {
                selector: IstioSelector {
                    match_labels: policy.selector.clone(),
                },
                rules,
                action: Some(IstioAuthzAction { allow: true }),
            },
        })
    }

    /// Apply Istio VirtualService via Kubernetes API
    async fn apply_istio_virtual_service(&self, vsvc: &IstioVirtualService) -> Result<()> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| FortressError::mesh("Istio client not initialized"))?;

        let url = format!("http://localhost:8080/apis/networking.istio.io/v1beta1/namespaces/{}/virtualservices/{}", 
                        vsvc.metadata.namespace, vsvc.metadata.name);

        let vsvc_json = serde_json::to_value(vsvc).map_err(|e| {
            FortressError::mesh(format!("Failed to serialize VirtualService: {}", e))
        })?;

        let response = client
            .put(&url)
            .json(&vsvc_json)
            .send()
            .await
            .map_err(|e| {
                FortressError::mesh(format!("Istio VirtualService API request failed: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(FortressError::mesh(format!(
                "Istio VirtualService API returned status: {}",
                response.status()
            )));
        }

        tracing::info!("Applied Istio VirtualService: {}", vsvc.metadata.name);
        Ok(())
    }

    /// Apply Istio AuthorizationPolicy via Kubernetes API
    async fn apply_istio_authz_policy(&self, authz: &IstioAuthzPolicy) -> Result<()> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| FortressError::mesh("Istio client not initialized"))?;

        let url = format!("http://localhost:8080/apis/security.istio.io/v1beta1/namespaces/{}/authorizationpolicies/{}", 
                        authz.metadata.namespace, authz.metadata.name);

        let authz_json = serde_json::to_value(authz).map_err(|e| {
            FortressError::mesh(format!("Failed to serialize AuthorizationPolicy: {}", e))
        })?;

        let response = client
            .put(&url)
            .json(&authz_json)
            .send()
            .await
            .map_err(|e| {
                FortressError::mesh(format!(
                    "Istio AuthorizationPolicy API request failed: {}",
                    e
                ))
            })?;

        if !response.status().is_success() {
            return Err(FortressError::mesh(format!(
                "Istio AuthorizationPolicy API returned status: {}",
                response.status()
            )));
        }

        tracing::info!("Applied Istio AuthorizationPolicy: {}", authz.metadata.name);
        Ok(())
    }

    /// Get Istio metrics
    async fn get_istio_metrics(&self) -> Result<IstioMetrics> {
        // Get metrics from Istio telemetry
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| FortressError::mesh("Istio client not initialized"))?;

        let url = "http://localhost:15090/stats";

        let response =
            client.get(url).send().await.map_err(|e| {
                FortressError::mesh(format!("Istio metrics API request failed: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(FortressError::mesh(format!(
                "Istio metrics API returned status: {}",
                response.status()
            )));
        }

        let metrics_text = response.text().await.map_err(|e| {
            FortressError::mesh(format!("Failed to read Istio metrics response: {}", e))
        })?;

        self.parse_istio_metrics(&metrics_text)
    }

    /// Parse Istio metrics from text format
    fn parse_istio_metrics(&self, metrics_text: &str) -> Result<IstioMetrics> {
        let mut metrics = IstioMetrics::default();

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
                    name if name.contains("connection_active") => {
                        metrics.connection_active += value.parse().unwrap_or(0);
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
impl MeshProvider for IstioMesh {
    fn name(&self) -> &str {
        "istio"
    }

    fn mesh_type(&self) -> MeshType {
        MeshType::Istio
    }

    async fn initialize(&mut self, config: &MeshConfig) -> Result<()> {
        // Extract Istio-specific config
        let istio_config: IstioMeshConfig =
            serde_json::from_value(serde_json::to_value(&config.settings).unwrap_or_default())
                .unwrap_or_default();

        self.config = istio_config;

        // Create HTTP client
        self.client = Some(self.create_client());
        self.initialized = true;

        tracing::info!("Istio mesh provider initialized");
        Ok(())
    }

    async fn get_mesh_nodes(&self) -> Result<Vec<MeshNode>> {
        if !self.initialized {
            return Err(FortressError::mesh("Istio mesh provider not initialized"));
        }

        let mut nodes = Vec::new();

        // Get services and convert to mesh nodes
        match self.get_istio_services().await {
            Ok(services) => {
                for service in services {
                    match self.istio_service_to_mesh_node(&service) {
                        Ok(node) => nodes.push(node),
                        Err(e) => {
                            tracing::warn!("Failed to convert Istio service to mesh node: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to get Istio services: {}", e);
            }
        }

        tracing::debug!("Istio mesh found {} nodes", nodes.len());
        Ok(nodes)
    }

    async fn get_traffic_policies(&self) -> Result<Vec<TrafficPolicy>> {
        if !self.initialized {
            return Err(FortressError::mesh("Istio mesh provider not initialized"));
        }

        let mut policies = Vec::new();

        // Get virtual services and convert to traffic policies
        match self.get_istio_virtual_services().await {
            Ok(virtual_services) => {
                for vsvc in virtual_services {
                    match self.istio_virtual_service_to_traffic_policy(&vsync) {
                        Ok(policy) => policies.push(policy),
                        Err(e) => {
                            tracing::warn!(
                                "Failed to convert Istio VirtualService to traffic policy: {}",
                                e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to get Istio VirtualServices: {}", e);
            }
        }

        Ok(policies)
    }

    async fn get_security_policies(&self) -> Result<Vec<SecurityPolicy>> {
        if !self.initialized {
            return Err(FortressError::mesh("Istio mesh provider not initialized"));
        }

        let mut policies = Vec::new();

        // Get authorization policies and convert to security policies
        match self.get_istio_authz_policies().await {
            Ok(authz_policies) => {
                for authz in authz_policies {
                    match self.istio_authz_policy_to_security_policy(&authz) {
                        Ok(policy) => policies.push(policy),
                        Err(e) => {
                            tracing::warn!("Failed to convert Istio AuthorizationPolicy to security policy: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to get Istio AuthorizationPolicies: {}", e);
            }
        }

        Ok(policies)
    }

    async fn apply_traffic_policy(&self, policy: &TrafficPolicy) -> Result<()> {
        if !self.initialized {
            return Err(FortressError::mesh("Istio mesh provider not initialized"));
        }

        self.apply_istio_traffic_policy(policy).await
    }

    async fn apply_security_policy(&self, policy: &SecurityPolicy) -> Result<()> {
        if !self.initialized {
            return Err(FortressError::mesh("Istio mesh provider not initialized"));
        }

        self.apply_istio_security_policy(policy).await
    }

    async fn get_metrics(&self) -> Result<MeshMetrics> {
        if !self.initialized {
            return Err(FortressError::mesh("Istio mesh provider not initialized"));
        }

        let istio_metrics = self.get_istio_metrics().await?;

        Ok(MeshMetrics {
            request_count: istio_metrics.request_total,
            request_duration_ms: 0, // Would need to calculate from histogram stats
            request_error_count: istio_metrics.request_failure_total,
            request_success_rate: if istio_metrics.request_total > 0 {
                (istio_metrics.request_total - istio_metrics.request_failure_total) as f64
                    / istio_metrics.request_total as f64
            } else {
                0.0
            },
            connection_count: istio_metrics.connection_total,
            active_connections: istio_metrics.connection_active,
            last_updated: istio_metrics.last_updated,
        })
    }

    async fn check_mesh_health(&self) -> Result<MeshNodeHealthStatus> {
        if !self.initialized {
            return Err(FortressError::mesh("Istio mesh provider not initialized"));
        }

        // Check if Istio Pilot API is accessible
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| FortressError::mesh("Istio client not initialized"))?;

        let url = format!("{}/v1/registration", self.config.pilot_address);

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

        tracing::info!("Istio mesh provider shutdown");
        Ok(())
    }
}

// Istio data structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioService {
    pub name: String,
    pub namespace: String,
    pub service_type: String,
    pub service_account: String,
    pub labels: HashMap<String, String>,
    pub endpoints: Vec<IstioEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioEndpoint {
    pub address: Option<String>,
    pub port: u16,
    pub healthy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioVirtualService {
    pub metadata: IstioMetadata,
    pub spec: IstioVirtualServiceSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioMetadata {
    pub name: String,
    pub namespace: String,
    pub creation_timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioVirtualServiceSpec {
    pub hosts: Vec<String>,
    pub gateways: Vec<String>,
    pub http: Vec<IstioHttpRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioHttpRoute {
    pub r#match: Vec<IstioMatchCondition>,
    pub route: Vec<IstioRouteDestination>,
    pub timeout: Option<String>,
    pub retries: Option<IstioRetry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioMatchCondition {
    pub name: String,
    pub value: String,
    pub regex: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioRouteDestination {
    pub destination: IstioDestination,
    pub weight: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioDestination {
    pub host: String,
    pub subset: Option<String>,
    pub port: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioRetry {
    pub attempts: u32,
    pub per_try_timeout: Option<String>,
    pub retry_on: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioDestinationRule {
    pub metadata: IstioMetadata,
    pub spec: IstioDestinationRuleSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioDestinationRuleSpec {
    pub host: String,
    pub traffic_policy: Option<IstioTrafficPolicy>,
    pub subsets: Vec<IstioSubset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioTrafficPolicy {
    pub load_balancer: Option<IstioLoadBalancer>,
    pub connection_pool: Option<IstioConnectionPool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioLoadBalancer {
    pub simple: Option<IstioSimpleLB>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioSimpleLB {
    pub round_robin: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioConnectionPool {
    pub tcp: Option<IstioTCPSettings>,
    pub http: Option<IstioHTTPSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioTCPSettings {
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioHTTPSettings {
    pub http1_max_pending_requests: u32,
    pub http2_max_requests: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioSubset {
    pub name: String,
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioAuthzPolicy {
    pub metadata: IstioMetadata,
    pub spec: IstioAuthzPolicySpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioAuthzPolicySpec {
    pub selector: IstioSelector,
    pub rules: Vec<IstioAuthzPolicyRule>,
    pub action: Option<IstioAuthzAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioSelector {
    pub match_labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioAuthzPolicyRule {
    pub name: Option<String>,
    pub when: Vec<IstioAuthzCondition>,
    pub action: Option<IstioAuthzAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioAuthzCondition {
    pub key: String,
    pub values: Option<Vec<String>>,
    pub not_values: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IstioAuthzAction {
    pub allow: bool,
}

#[derive(Debug, Clone, Default)]
pub struct IstioMetrics {
    pub request_total: u64,
    pub request_success_total: u64,
    pub request_failure_total: u64,
    pub connection_total: u64,
    pub connection_active: u64,
    pub last_updated: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_istio_config_default() {
        let config = IstioMeshConfig::default();
        assert_eq!(
            config.pilot_address,
            "http://istio-pilot.istio-system:15014"
        );
        assert_eq!(config.namespace, "default");
        assert!(config.service_discovery_enabled);
        assert!(config.traffic_management_enabled);
        assert!(config.security_enabled);
    }

    #[test]
    fn test_istio_mesh_creation() {
        let config = IstioMeshConfig::default();
        let mesh = IstioMesh::new(config);

        assert_eq!(mesh.name(), "istio");
        assert_eq!(mesh.mesh_type(), MeshType::Istio);
        assert!(!mesh.initialized);
        assert!(mesh.client.is_none());
    }
}
