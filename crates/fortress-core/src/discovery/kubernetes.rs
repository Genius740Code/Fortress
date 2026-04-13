//! Kubernetes Discovery Provider
//! 
//! This module provides automatic discovery of Fortress cluster nodes
//! within a Kubernetes environment using the Kubernetes API.

use std::collections::HashMap;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use crate::error::{FortressError, Result};
use crate::discovery::{DiscoveryProvider, DiscoveredNode, NodeHealthStatus, DiscoveryConfig};

/// Kubernetes discovery provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesDiscoveryConfig {
    pub namespace: String,
    pub label_selector: Option<String>,
    pub field_selector: Option<String>,
    pub service_name: Option<String>,
    pub port_name: Option<String>,
    pub kubeconfig_path: Option<String>,
    pub in_cluster: bool,
    pub api_timeout_seconds: u64,
}

impl Default for KubernetesDiscoveryConfig {
    fn default() -> Self {
        Self {
            namespace: "default".to_string(),
            label_selector: Some("app=fortress".to_string()),
            field_selector: None,
            service_name: None,
            port_name: Some("api".to_string()),
            kubeconfig_path: None,
            in_cluster: true,
            api_timeout_seconds: 30,
        }
    }
}

/// Kubernetes discovery provider
pub struct KubernetesDiscovery {
    config: KubernetesDiscoveryConfig,
    client: Option<kube::Client>,
    initialized: bool,
    node_cache: Arc<RwLock<HashMap<String, DiscoveredNode>>>,
}

impl KubernetesDiscovery {
    /// Create a new Kubernetes discovery provider
    pub fn new(config: KubernetesDiscoveryConfig) -> Self {
        Self {
            config,
            client: None,
            initialized: false,
            node_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create Kubernetes client
    async fn create_client(&self) -> Result<Option<kube::Client>> {
        if self.config.in_cluster {
            // Use in-cluster configuration
            match kube::Client::try_default().await {
                Ok(client) => Ok(Some(client)),
                Err(e) => {
                    tracing::warn!("Failed to create in-cluster Kubernetes client: {}", e);
                    Ok(None)
                }
            }
        } else {
            // Use kubeconfig
            match kube::Config::from_kubeconfig().await {
                Ok(config) => {
                    match kube::Client::try_from(config).await {
                        Ok(client) => Ok(Some(client)),
                        Err(e) => {
                            tracing::warn!("Failed to create Kubernetes client from kubeconfig: {}", e);
                            Ok(None)
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to load kubeconfig: {}", e);
                    Ok(None)
                }
            }
        }
    }

    /// Get pods using label selector
    async fn get_pods(&self) -> Result<Vec<kube::api::Pod>> {
        let client = match &self.client {
            Some(client) => client,
            None => return Ok(Vec::new()),
        };

        let pods: kube::api::Api<kube::api::Pod> = kube::api::Api::namespaced(
            client.clone(),
            &self.config.namespace,
        );

        match pods.list(&kube::api::ListParams::default().labels(&self.config.label_selector.as_ref().unwrap_or(&"".to_string()))).await {
            Ok(pod_list) => Ok(pod_list.items),
            Err(e) => {
                tracing::warn!("Failed to list pods: {}", e);
                Ok(Vec::new())
            }
        }
    }

    /// Get services
    async fn get_services(&self) -> Result<Vec<kube::api::Service>> {
        let client = match &self.client {
            Some(client) => client,
            None => return Ok(Vec::new()),
        };

        let services: kube::api::Api<kube::api::Service> = kube::api::Api::namespaced(
            client.clone(),
            &self.config.namespace
        );

        match services.list(&kube::api::ListParams::default()).await {
            Ok(service_list) => Ok(service_list.items),
            Err(e) => {
                tracing::warn!("Failed to list services: {}", e);
                Ok(Vec::new())
            }
        }
    }

    /// Extract node information from a pod
    fn pod_to_node(&self, pod: &kube::api::Pod) -> Result<DiscoveredNode> {
        let pod_name = pod.metadata.name.as_ref()
            .ok_or_else(|| FortressError::discovery("Pod missing name"))?;

        let pod_ip = pod.status.as_ref()
            .and_then(|status| status.pod_ip.as_ref())
            .ok_or_else(|| FortressError::discovery("Pod missing IP address"))?;

        // Extract port from container or service
        let port = self.extract_port_from_pod(pod)?;

        // Extract labels as tags
        let mut tags = HashMap::new();
        if let Some(ref labels) = pod.metadata.labels {
            for (key, value) in labels {
                tags.insert(key.clone(), value.clone());
            }
        }

        // Extract annotations as metadata
        let mut metadata = HashMap::new();
        if let Some(ref annotations) = pod.metadata.annotations {
            for (key, value) in annotations {
                metadata.insert(key.clone(), value.clone());
            }
        }

        // Add pod-specific metadata
        metadata.insert("pod_name".to_string(), pod_name.clone());
        metadata.insert("pod_namespace".to_string(), self.config.namespace.clone());
        metadata.insert("pod_ip".to_string(), pod_ip.clone());

        // Extract node information
        let mut region = None;
        let mut zone = None;
        if let Some(ref node_name) = pod.spec.as_ref().and_then(|spec| spec.node_name.as_ref()) {
            metadata.insert("node_name".to_string(), node_name.clone());
            
            // Try to extract region/zone from node labels (cloud provider specific)
            // This would require additional API calls to get node details
        }

        // Determine health status
        let health_status = self.pod_health_status(pod);

        // Extract capabilities from labels or annotations
        let mut capabilities = Vec::new();
        if let Some(capability_list) = metadata.get("capabilities") {
            capabilities = capability_list.split(',').map(|s| s.trim().to_string()).collect();
        }

        Ok(DiscoveredNode {
            id: format!("kube-pod-{}", pod_name),
            address: pod_ip.clone(),
            port,
            region,
            zone,
            tags,
            metadata,
            last_seen: Utc::now(),
            health_status,
            capabilities,
        })
    }

    /// Extract node information from a service
    fn service_to_node(&self, service: &kube::api::Service) -> Result<DiscoveredNode> {
        let service_name = service.metadata.name.as_ref()
            .ok_or_else(|| FortressError::discovery("Service missing name"))?;

        let service_ip = service.spec.as_ref()
            .and_then(|spec| spec.cluster_ip.as_ref())
            .ok_or_else(|| FortressError::discovery("Service missing cluster IP"))?;

        // Extract port from service
        let port = self.extract_port_from_service(service)?;

        // Extract labels as tags
        let mut tags = HashMap::new();
        if let Some(ref labels) = service.metadata.labels {
            for (key, value) in labels {
                tags.insert(key.clone(), value.clone());
            }
        }
        tags.insert("type".to_string(), "service".to_string());

        // Extract annotations as metadata
        let mut metadata = HashMap::new();
        if let Some(ref annotations) = service.metadata.annotations {
            for (key, value) in annotations {
                metadata.insert(key.clone(), value.clone());
            }
        }

        // Add service-specific metadata
        metadata.insert("service_name".to_string(), service_name.clone());
        metadata.insert("service_namespace".to_string(), self.config.namespace.clone());
        metadata.insert("service_ip".to_string(), service_ip.clone());
        metadata.insert("service_type".to_string(), format!("{:?}", service.spec.as_ref().map(|s| &s.service_type).unwrap_or(&kube::api::ServiceType::ClusterIP)));

        // Extract capabilities from labels or annotations
        let mut capabilities = Vec::new();
        if let Some(capability_list) = metadata.get("capabilities") {
            capabilities = capability_list.split(',').map(|s| s.trim().to_string()).collect();
        }

        Ok(DiscoveredNode {
            id: format!("kube-service-{}", service_name),
            address: service_ip.clone(),
            port,
            region: None,
            zone: None,
            tags,
            metadata,
            last_seen: Utc::now(),
            health_status: NodeHealthStatus::Healthy, // Services are generally considered healthy
            capabilities,
        })
    }

    /// Extract port from pod specification
    fn extract_port_from_pod(&self, pod: &kube::api::Pod) -> Result<u16> {
        // Check if a specific port name is configured
        if let Some(ref port_name) = self.config.port_name {
            if let Some(ref containers) = pod.spec.as_ref().and_then(|spec| spec.containers.as_ref()) {
                for container in containers {
                    if let Some(ref ports) = container.ports {
                        for port in ports {
                            if let Some(ref name) = port.name {
                                if name == port_name {
                                    return Ok(port.container_port as u16);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Default to first available port
        if let Some(ref containers) = pod.spec.as_ref().and_then(|spec| spec.containers.as_ref()) {
            for container in containers {
                if let Some(ref ports) = container.ports {
                    if let Some(first_port) = ports.first() {
                        return Ok(first_port.container_port as u16);
                    }
                }
            }
        }

        Err(FortressError::discovery("No port found in pod specification"))
    }

    /// Extract port from service specification
    fn extract_port_from_service(&self, service: &kube::api::Service) -> Result<u16> {
        // Check if a specific port name is configured
        if let Some(ref port_name) = self.config.port_name {
            if let Some(ref ports) = service.spec.as_ref().and_then(|spec| spec.ports.as_ref()) {
                for port in ports {
                    if let Some(ref name) = port.name {
                        if name == port_name {
                            return Ok(port.port as u16);
                        }
                    }
                }
            }
        }

        // Default to first available port
        if let Some(ref ports) = service.spec.as_ref().and_then(|spec| spec.ports.as_ref()) {
            if let Some(first_port) = ports.first() {
                return Ok(first_port.port as u16);
            }
        }

        Err(FortressError::discovery("No port found in service specification"))
    }

    /// Determine pod health status
    fn pod_health_status(&self, pod: &kube::api::Pod) -> NodeHealthStatus {
        if let Some(ref status) = pod.status {
            // Check pod phase
            if let Some(ref phase) = status.phase {
                match phase.as_str() {
                    "Running" => {
                        // Check if all containers are ready
                        if let Some(ref conditions) = status.conditions {
                            let ready_condition = conditions.iter()
                                .find(|c| c.type_ == "Ready");
                            
                            if let Some(ready) = ready_condition {
                                if ready.status == "True" {
                                    return NodeHealthStatus::Healthy;
                                }
                            }
                        }
                        NodeHealthStatus::Degraded
                    }
                    "Pending" => NodeHealthStatus::Degraded,
                    "Failed" | "Error" => NodeHealthStatus::Unhealthy,
                    "Succeeded" => NodeHealthStatus::Healthy, // Completed successfully
                    _ => NodeHealthStatus::Unknown,
                }
            } else {
                NodeHealthStatus::Unknown
            }
        } else {
            NodeHealthStatus::Unknown
        }
    }

    /// Check if a pod is ready
    async fn check_pod_ready(&self, pod_name: &str) -> Result<NodeHealthStatus> {
        let client = self.client.as_ref()
            .ok_or_else(|| FortressError::discovery("Kubernetes client not initialized"))?;

        let pods: kube::api::Api<kube::api::Pod> = kube::api::Api::namespaced(
            client.clone(),
            &self.config.namespace
        );

        match pods.get(pod_name).await {
            Ok(pod) => Ok(self.pod_health_status(&pod)),
            Err(_) => Ok(NodeHealthStatus::Unknown),
        }
    }
}

#[async_trait::async_trait]
impl DiscoveryProvider for KubernetesDiscovery {
    fn name(&self) -> &str {
        "kubernetes"
    }

    async fn initialize(&mut self, config: &DiscoveryConfig) -> Result<()> {
        // Extract Kubernetes-specific config
        let k8s_config: KubernetesDiscoveryConfig = serde_json::from_value(
            serde_json::to_value(&config.settings).unwrap_or_default()
        ).unwrap_or_default();

        self.config = k8s_config;

        // Create Kubernetes client
        self.client = self.create_client().await?;
        self.initialized = true;

        tracing::info!("Kubernetes discovery provider initialized");
        Ok(())
    }

    async fn discover_nodes(&self) -> Result<Vec<DiscoveredNode>> {
        if !self.initialized {
            return Err(FortressError::discovery("Kubernetes discovery provider not initialized"));
        }

        let mut nodes = Vec::new();

        // Discover pods
        match self.get_pods().await {
            Ok(pods) => {
                for pod in pods {
                    match self.pod_to_node(&pod) {
                        Ok(node) => nodes.push(node),
                        Err(e) => {
                            tracing::warn!("Failed to convert pod to node: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to get pods: {}", e);
            }
        }

        // Discover services
        match self.get_services().await {
            Ok(services) => {
                for service in services {
                    match self.service_to_node(&service) {
                        Ok(node) => nodes.push(node),
                        Err(e) => {
                            tracing::warn!("Failed to convert service to node: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to get services: {}", e);
            }
        }

        tracing::debug!("Kubernetes discovery found {} nodes", nodes.len());
        Ok(nodes)
    }

    async fn check_node_health(&self, node: &DiscoveredNode) -> Result<NodeHealthStatus> {
        if !self.initialized {
            return Err(FortressError::discovery("Kubernetes discovery provider not initialized"));
        }

        // Extract pod name from node ID if it's a pod
        if node.id.starts_with("kube-pod-") {
            let pod_name = node.id.strip_prefix("kube-pod-")
                .ok_or_else(|| FortressError::discovery("Invalid pod node ID"))?;
            
            return self.check_pod_ready(pod_name).await;
        }

        // For services, assume they're healthy if they exist
        if node.id.starts_with("kube-service-") {
            return Ok(NodeHealthStatus::Healthy);
        }

        Ok(NodeHealthStatus::Unknown)
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.client = None;
        self.initialized = false;
        tracing::info!("Kubernetes discovery provider shutdown");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kubernetes_config_default() {
        let config = KubernetesDiscoveryConfig::default();
        assert_eq!(config.namespace, "default");
        assert_eq!(config.label_selector, Some("app=fortress".to_string()));
        assert!(config.in_cluster);
        assert_eq!(config.api_timeout_seconds, 30);
    }

    #[test]
    fn test_kubernetes_discovery_creation() {
        let config = KubernetesDiscoveryConfig::default();
        let discovery = KubernetesDiscovery::new(config);
        
        assert_eq!(discovery.name(), "kubernetes");
        assert!(!discovery.initialized);
        assert!(discovery.client.is_none());
    }
}
