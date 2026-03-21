//! Distributed tracing implementation for Fortress
//!
//! Provides OpenTelemetry-compatible distributed tracing with
//! span propagation, sampling, and export capabilities.

use crate::error::{FortressError, Result};

#[cfg(feature = "opentelemetry")]
use opentelemetry::trace::{Span, Tracer, TracerProvider};
#[cfg(feature = "opentelemetry")]
use opentelemetry::{global, KeyValue};
#[cfg(feature = "tracing-opentelemetry")]
use tracing_opentelemetry::OpenTelemetrySpanExt;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;

// Fallback Span trait for when OpenTelemetry is not available
#[cfg(not(feature = "opentelemetry"))]
pub trait Span: Send + Sync {
    /// Add an event to the span
    fn add_event(&mut self, name: &str, _attributes: Vec<String>);
    /// Add a link to the span
    fn add_link(&mut self, _link: String);
    /// Set the status of the span
    fn set_status(&mut self, _status: String);
    /// Set an attribute on the span
    fn set_attribute(&mut self, _attribute: String);
    /// End the span with a timestamp
    fn end_with_timestamp(&mut self, _timestamp: u64);
}

// Fallback Tracer trait for when OpenTelemetry is not available
#[cfg(not(feature = "opentelemetry"))]
pub trait Tracer: Send + Sync {
    /// Start a new span with context
    fn start_with_context(&self, name: &str) -> Box<dyn Span + Send + Sync>;
}

// Enum wrapper for Tracer implementations
#[cfg(not(feature = "opentelemetry"))]
#[derive(Debug)]
pub enum TracerImpl {
    /// No-operation tracer
    NoOp(NoOpTracer),
    /// Console tracer
    Console(ConsoleTracer),
}

#[cfg(not(feature = "opentelemetry"))]
impl Tracer for TracerImpl {
    fn start_with_context(&self, name: &str) -> Box<dyn Span + Send + Sync> {
        match self {
            TracerImpl::NoOp(tracer) => tracer.start_with_context(name),
            TracerImpl::Console(tracer) => tracer.start_with_context(name),
        }
    }
}

// Enum wrapper for Span implementations
#[cfg(not(feature = "opentelemetry"))]
pub enum SpanImpl {
    NoOp(NoOpSpan),
    Console(ConsoleSpan),
}

#[cfg(not(feature = "opentelemetry"))]
impl Span for SpanImpl {
    fn add_event(&mut self, name: &str, _attributes: Vec<String>) {
        match self {
            SpanImpl::NoOp(span) => span.add_event(name, _attributes),
            SpanImpl::Console(span) => span.add_event(name, _attributes),
        }
    }

    fn add_link(&mut self, _link: String) {
        match self {
            SpanImpl::NoOp(span) => span.add_link(_link),
            SpanImpl::Console(span) => span.add_link(_link),
        }
    }

    fn set_status(&mut self, _status: String) {
        match self {
            SpanImpl::NoOp(span) => span.set_status(_status),
            SpanImpl::Console(span) => span.set_status(_status),
        }
    }

    fn set_attribute(&mut self, _attribute: String) {
        match self {
            SpanImpl::NoOp(span) => span.set_attribute(_attribute),
            SpanImpl::Console(span) => span.set_attribute(_attribute),
        }
    }

    fn end_with_timestamp(&mut self, _timestamp: u64) {
        match self {
            SpanImpl::NoOp(span) => span.end_with_timestamp(_timestamp),
            SpanImpl::Console(span) => span.end_with_timestamp(_timestamp),
        }
    }
}

/// Distributed tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceConfig {
    /// Enable distributed tracing
    pub enabled: bool,
    /// Service name for tracing
    pub service_name: String,
    /// Service version
    pub service_version: String,
    /// Sampling configuration
    pub sampling: SamplingConfig,
    /// Export configuration
    pub export: ExportConfig,
    /// Span limits
    pub span_limits: SpanLimits,
}

/// Sampling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplingConfig {
    /// Sampling strategy
    pub strategy: SamplingStrategy,
    /// Sampling ratio (0.0 to 1.0)
    pub ratio: f64,
    /// Maximum number of spans per second
    pub spans_per_second: u32,
}

/// Sampling strategies
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SamplingStrategy {
    /// Always sample
    AlwaysOn,
    /// Never sample
    AlwaysOff,
    /// Sample based on ratio
    TraceIdRatio,
    /// Sample based on rate limit
    RateLimiting,
}

/// Export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    /// Exporter type
    pub exporter_type: ExporterType,
    /// Export endpoint
    pub endpoint: Option<String>,
    /// Export interval
    pub export_interval_seconds: u64,
    /// Export timeout
    pub export_timeout_seconds: u64,
    /// Batch configuration
    pub batch_config: BatchConfig,
}

/// Exporter types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ExporterType {
    /// Jaeger exporter
    Jaeger,
    /// Zipkin exporter
    Zipkin,
    /// OpenTelemetry collector
    OtelCollector,
    /// Console exporter (for debugging)
    Console,
    /// No exporter (for testing)
    None,
}

/// Batch export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    /// Maximum batch size
    pub max_batch_size: usize,
    /// Maximum export timeout
    pub max_export_timeout_seconds: u64,
    /// Maximum queue size
    pub max_queue_size: usize,
}

/// Span limits configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanLimits {
    /// Maximum number of attributes per span
    pub max_attributes_per_span: u32,
    /// Maximum number of events per span
    pub max_events_per_span: u32,
    /// Maximum number of links per span
    pub max_links_per_span: u32,
    /// Maximum attribute length
    pub max_attribute_length: u32,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            service_name: "fortress".to_string(),
            service_version: "0.1.0".to_string(),
            sampling: SamplingConfig::default(),
            export: ExportConfig::default(),
            span_limits: SpanLimits::default(),
        }
    }
}

impl Default for SamplingConfig {
    fn default() -> Self {
        Self {
            strategy: SamplingStrategy::TraceIdRatio,
            ratio: 0.1, // 10% sampling
            spans_per_second: 1000,
        }
    }
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            exporter_type: ExporterType::Console,
            endpoint: None,
            export_interval_seconds: 5,
            export_timeout_seconds: 30,
            batch_config: BatchConfig::default(),
        }
    }
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 512,
            max_export_timeout_seconds: 30,
            max_queue_size: 2048,
        }
    }
}

impl Default for SpanLimits {
    fn default() -> Self {
        Self {
            max_attributes_per_span: 128,
            max_events_per_span: 128,
            max_links_per_span: 128,
            max_attribute_length: 1024,
        }
    }
}

/// Span context for trace propagation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanContext {
    /// Trace ID
    pub trace_id: String,
    /// Span ID
    pub span_id: String,
    /// Parent span ID (if any)
    pub parent_span_id: Option<String>,
    /// Trace flags
    pub trace_flags: u8,
    /// Trace state
    pub trace_state: String,
    /// Baggage items
    pub baggage: HashMap<String, String>,
}

/// Observability tracer with OpenTelemetry integration
#[derive(Debug)]
pub struct ObservabilityTracer {
    /// Configuration
    config: TraceConfig,
    /// OpenTelemetry tracer
    #[cfg(feature = "opentelemetry")]
    tracer: Box<dyn opentelemetry::trace::Tracer + Send + Sync>,
    #[cfg(not(feature = "opentelemetry"))]
    tracer: TracerImpl,
    /// Active spans registry
    active_spans: tokio::sync::RwLock<HashMap<String, ActiveSpan>>,
}

/// Active span information
#[derive(Debug, Clone)]
struct ActiveSpan {
    /// Span ID
    span_id: String,
    /// Operation name
    operation_name: String,
    /// Start time
    start_time: Instant,
    /// Span context
    context: SpanContext,
    /// Attributes
    attributes: HashMap<String, String>,
}

impl ObservabilityTracer {
    /// Create a new observability tracer
    pub fn new(config: TraceConfig) -> Result<Self> {
        if !config.enabled {
            // Create a no-op tracer for disabled tracing
            return Ok(Self {
                config,
                tracer: TracerImpl::NoOp(NoOpTracer),
                active_spans: tokio::sync::RwLock::new(HashMap::new()),
            });
        }

        // Initialize OpenTelemetry tracer based on configuration
        #[cfg(feature = "opentelemetry")]
        let tracer = Self::create_otel_tracer(&config)?;
        
        #[cfg(not(feature = "opentelemetry"))]
        let tracer = TracerImpl::Console(ConsoleTracer::new(TracerConfig::default()));

        Ok(Self {
            config,
            tracer,
            active_spans: tokio::sync::RwLock::new(HashMap::new()),
        })
    }
}

/// Tracer configuration for when OpenTelemetry is not available
#[cfg(not(feature = "opentelemetry"))]
#[derive(Debug)]
pub struct TracerConfig {
    /// Whether tracing is enabled
    pub enabled: bool,
    /// Name of the service being traced
    pub service_name: String,
    /// Version of the service being traced
    pub service_version: String,
}

impl Default for TracerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            service_name: "fortress".to_string(),
            service_version: "0.1.0".to_string(),
        }
    }
}

/// Create OpenTelemetry tracer based on configuration
#[cfg(feature = "opentelemetry")]
fn create_otel_tracer(config: &TraceConfig) -> Result<Box<dyn opentelemetry::trace::Tracer + Send + Sync>> {
    match config.export.exporter_type {
        ExporterType::Console => {
            // For now, return a no-op tracer that logs to console
            // In a full implementation, this would set up OpenTelemetry with console exporter
            Ok(Box::new(ConsoleTracer))
        }
        ExporterType::Jaeger => {
            // Would set up Jaeger exporter
            tracing::warn!("Jaeger exporter not yet implemented, using console tracer");
            Ok(Box::new(ConsoleTracer))
        }
        ExporterType::Zipkin => {
            // Would set up Zipkin exporter
            tracing::warn!("Zipkin exporter not yet implemented, using console tracer");
            Ok(Box::new(ConsoleTracer))
        }
        ExporterType::OtelCollector => {
            // Would set up OTLP exporter
            tracing::warn!("OTLP exporter not yet implemented, using console tracer");
            Ok(Box::new(ConsoleTracer))
        }
        ExporterType::None => {
            Ok(Box::new(NoOpTracer))
        }
    }
}

impl ObservabilityTracer {
    /// Start a new span
    pub async fn start_span(
        &self,
        operation_name: &str,
        parent_context: Option<&SpanContext>,
        attributes: HashMap<String, String>,
    ) -> Result<SpanContext> {
        if !self.config.enabled {
            return Ok(SpanContext::empty());
        }

        let span_id = Uuid::new_v4().to_string();
        let trace_id = parent_context
            .map(|ctx| ctx.trace_id.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let context = SpanContext {
            trace_id: trace_id.clone(),
            span_id: span_id.clone(),
            parent_span_id: parent_context.map(|ctx| ctx.span_id.clone()),
            trace_flags: 1, // Sampled
            trace_state: String::new(),
            baggage: HashMap::new(),
        };

        // Register active span
        let active_span = ActiveSpan {
            span_id: span_id.clone(),
            operation_name: operation_name.to_string(),
            start_time: Instant::now(),
            context: context.clone(),
            attributes: attributes,
        };

        let mut active_spans = self.active_spans.write().await;
        active_spans.insert(span_id.clone(), active_span);

        // Create OpenTelemetry span (simplified for now)
        #[cfg(feature = "opentelemetry")]
        let _span = self.tracer.start_with_context(operation_name);
        
        #[cfg(not(feature = "opentelemetry"))]
        let _span = self.tracer.start_with_context(operation_name);

        tracing::info!(
            trace_id = %trace_id,
            span_id = %span_id,
            operation = %operation_name,
            "Started span"
        );

        Ok(context)
    }

    /// Finish a span
    pub async fn finish_span(
        &self,
        span_context: &SpanContext,
        result: Option<&str>,
        error: Option<&str>,
    ) -> Result<()> {
        if !self.config.enabled || span_context.is_empty() {
            return Ok(());
        }

        let mut active_spans = self.active_spans.write().await;
        if let Some(active_span) = active_spans.remove(&span_context.span_id) {
            let duration = active_span.start_time.elapsed();

            // Log span completion
            if let Some(error) = error {
                tracing::error!(
                    trace_id = %span_context.trace_id,
                    span_id = %span_context.span_id,
                    operation = %active_span.operation_name,
                    duration_ms = duration.as_millis(),
                    error = %error,
                    "Span completed with error"
                );
            } else {
                tracing::info!(
                    trace_id = %span_context.trace_id,
                    span_id = %span_context.span_id,
                    operation = %active_span.operation_name,
                    duration_ms = duration.as_millis(),
                    result = ?result,
                    "Span completed successfully"
                );
            }
        }

        Ok(())
    }

    /// Add event to span
    pub async fn add_span_event(
        &self,
        span_context: &SpanContext,
        event_name: &str,
        _attributes: HashMap<String, String>,
    ) -> Result<()> {
        if !self.config.enabled || span_context.is_empty() {
            return Ok(());
        }

        tracing::info!(
            trace_id = %span_context.trace_id,
            span_id = %span_context.span_id,
            event = %event_name,
            "Span event"
        );

        Ok(())
    }

    /// Extract span context from headers
    pub fn extract_context(&self, headers: &HashMap<String, String>) -> Result<Option<SpanContext>> {
        if !self.config.enabled {
            return Ok(None);
        }

        // Look for traceparent header (W3C trace context)
        if let Some(traceparent) = headers.get("traceparent") {
            return Ok(Some(SpanContext::from_traceparent(traceparent)?));
        }

        // Look for legacy headers
        if let (Some(trace_id), Some(span_id)) = (
            headers.get("x-trace-id"),
            headers.get("x-span-id"),
        ) {
            return Ok(Some(SpanContext {
                trace_id: trace_id.clone(),
                span_id: span_id.clone(),
                parent_span_id: headers.get("x-parent-span-id").cloned(),
                trace_flags: 1,
                trace_state: String::new(),
                baggage: HashMap::new(),
            }));
        }

        Ok(None)
    }

    /// Inject span context into headers
    #[cfg(feature = "tracing-opentelemetry")]
    pub fn inject_context(&self, context: &SpanContext, headers: &mut HashMap<String, String>) -> Result<()> {
        if !self.config.enabled || context.is_empty() {
            return Ok(());
        }

        // Inject W3C traceparent header
        headers.insert("traceparent".to_string(), context.to_traceparent()?);
        
        // Also inject legacy headers for compatibility
        headers.insert("x-trace-id".to_string(), context.trace_id.clone());
        headers.insert("x-span-id".to_string(), context.span_id.clone());
        
        if let Some(parent_span_id) = &context.parent_span_id {
            headers.insert("x-parent-span-id".to_string(), parent_span_id.clone());
        }

        Ok(())
    }

    /// Inject span context into headers (no-op when feature not enabled)
    #[cfg(not(feature = "tracing-opentelemetry"))]
    /// Inject span context into HTTP headers for distributed tracing
    /// 
    /// # Arguments
    /// * `context` - Span context to inject
    /// * `headers` - HTTP headers to inject into
    pub fn inject_context(&self, context: &SpanContext, headers: &mut HashMap<String, String>) -> Result<()> {
        if !self.config.enabled || context.is_empty() {
            return Ok(());
        }

        // Inject legacy headers only
        headers.insert("x-trace-id".to_string(), context.trace_id.clone());
        headers.insert("x-span-id".to_string(), context.span_id.clone());
        
        if let Some(parent_span_id) = &context.parent_span_id {
            headers.insert("x-parent-span-id".to_string(), parent_span_id.clone());
        }

        Ok(())
    }

    /// Get active spans from the tracer
    /// 
    /// # Returns
    /// * `Vec<ActiveSpanInfo>` - List of active span information
    pub async fn get_active_spans(&self) -> Result<Vec<ActiveSpanInfo>> {
        let active_spans = self.active_spans.read().await;
        let spans: Vec<ActiveSpanInfo> = active_spans
            .values()
            .map(|span| ActiveSpanInfo {
                span_id: span.span_id.clone(),
                operation_name: span.operation_name.clone(),
                duration_ms: span.start_time.elapsed().as_millis() as u64,
                trace_id: span.context.trace_id.clone(),
            })
            .collect();

        Ok(spans)
    }

    /// Start the distributed tracer
    /// 
    /// # Returns
    /// * `Result<()>` - Success status
    pub async fn start(&self) -> Result<()> {
        if self.config.enabled {
            tracing::info!("Distributed tracing started");
        }
        Ok(())
    }

    /// Shutdown the distributed tracer
    /// 
    /// # Returns
    /// * `Result<()>` - Success status
    pub async fn shutdown(&self) -> Result<()> {
        if self.config.enabled {
            // Finish any remaining active spans
            let mut active_spans = self.active_spans.write().await;
            let span_count = active_spans.len();
            active_spans.clear();
            
            if span_count > 0 {
                tracing::warn!("Shutdown with {} active spans", span_count);
            }

            tracing::info!("Distributed tracing shutdown");
        }
        Ok(())
    }
}

/// Information about active span
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSpanInfo {
    /// Span ID
    pub span_id: String,
    /// Operation name
    pub operation_name: String,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Trace ID
    pub trace_id: String,
}

impl SpanContext {
    /// Create empty span context
    pub fn empty() -> Self {
        Self {
            trace_id: String::new(),
            span_id: String::new(),
            parent_span_id: None,
            trace_flags: 0,
            trace_state: String::new(),
            baggage: HashMap::new(),
        }
    }

    /// Check if context is empty
    pub fn is_empty(&self) -> bool {
        self.trace_id.is_empty() || self.span_id.is_empty()
    }

    /// Create from traceparent header
    pub fn from_traceparent(traceparent: &str) -> Result<Self> {
        // Parse W3C traceparent format: version-trace_id-span_id-flags
        let parts: Vec<&str> = traceparent.split('-').collect();
        if parts.len() != 4 {
            return Err(FortressError::validation(
                "Invalid traceparent format".to_string(),
                None,
                None,
            ));
        }

        let trace_id = parts[1].to_string();
        let span_id = parts[2].to_string();
        let trace_flags = u8::from_str_radix(parts[3], 16)
            .map_err(|_| FortressError::validation("Invalid trace flags".to_string(), None, None))?;

        Ok(Self {
            trace_id,
            span_id,
            parent_span_id: None,
            trace_flags,
            trace_state: String::new(),
            baggage: HashMap::new(),
        })
    }

    /// Convert to traceparent header
    pub fn to_traceparent(&self) -> Result<String> {
        if self.is_empty() {
            return Ok(String::new());
        }

        let version = "00";
        let flags = format!("{:02x}", self.trace_flags);
        Ok(format!("{}-{}-{}-{}", version, self.trace_id, self.span_id, flags))
    }
}

/// No-op tracer implementation
#[derive(Debug)]
struct NoOpTracer;

#[cfg(feature = "opentelemetry")]
impl Tracer for NoOpTracer {
    fn start_with_context<T>(&self, name: &str, _context: &T) -> Box<dyn Span + Send + Sync> {
        Box::new(NoOpSpan::new(name.to_string()))
    }
}

#[cfg(not(feature = "opentelemetry"))]
impl Tracer for NoOpTracer {
    fn start_with_context(&self, name: &str) -> Box<dyn Span + Send + Sync> {
        Box::new(NoOpSpan::new(name.to_string()))
    }
}

/// Console tracer implementation
#[derive(Debug)]
struct ConsoleTracer {
    config: TracerConfig,
}

impl ConsoleTracer {
    fn new(config: TracerConfig) -> Self {
        Self { config }
    }
}

#[cfg(feature = "opentelemetry")]
impl Tracer for ConsoleTracer {
    fn start_with_context<T>(&self, name: &str, _context: &T) -> Box<dyn Span + Send + Sync> {
        Box::new(ConsoleSpan::new(name.to_string()))
    }
}

#[cfg(not(feature = "opentelemetry"))]
impl Tracer for ConsoleTracer {
    fn start_with_context(&self, name: &str) -> Box<dyn Span + Send + Sync> {
        Box::new(ConsoleSpan::new(name.to_string()))
    }
}

/// No-op span implementation
struct NoOpSpan {
    name: String,
}

impl NoOpSpan {
    fn new(name: String) -> Self {
        Self { name }
    }
}

#[cfg(feature = "opentelemetry")]
impl Span for NoOpSpan {
    fn add_event<T>(&mut self, _name: T, _attributes: Vec<KeyValue>) {}
    fn add_link(&mut self, _link: opentelemetry::trace::Link) {}
    fn set_status(&mut self, _status: opentelemetry::trace::Status) {}
    fn set_attribute(&mut self, _attribute: KeyValue) {}
    fn end_with_timestamp(&mut self, _timestamp: opentelemetry::time::Timestamp) {}
}

#[cfg(not(feature = "opentelemetry"))]
impl Span for NoOpSpan {
    fn add_event(&mut self, _name: &str, _attributes: Vec<String>) {}
    fn add_link(&mut self, _link: String) {}
    fn set_status(&mut self, _status: String) {}
    fn set_attribute(&mut self, _attribute: String) {}
    fn end_with_timestamp(&mut self, _timestamp: u64) {}
}

/// Console span implementation
struct ConsoleSpan {
    name: String,
    start_time: std::time::Instant,
}

impl ConsoleSpan {
    fn new(name: String) -> Self {
        tracing::info!("Starting span: {}", name);
        Self {
            name,
            start_time: std::time::Instant::now(),
        }
    }
}

#[cfg(feature = "opentelemetry")]
impl Span for ConsoleSpan {
    fn add_event<T>(&mut self, name: T, _attributes: Vec<KeyValue>) {
        tracing::info!("Span event: {}", format!("{}", name));
    }

    fn add_link(&mut self, _link: opentelemetry::trace::Link) {}

    fn set_status(&mut self, _status: opentelemetry::trace::Status) {}

    fn set_attribute(&mut self, attribute: KeyValue) {
        tracing::info!("Span attribute: {} = {}", attribute.key, attribute.value);
    }

    fn end_with_timestamp(&mut self, _timestamp: opentelemetry::time::Timestamp) {
        let duration = self.start_time.elapsed();
        tracing::info!("Finished span: {} (duration: {:?})", self.name, duration);
    }
}

#[cfg(not(feature = "opentelemetry"))]
impl Span for ConsoleSpan {
    fn add_event(&mut self, name: &str, _attributes: Vec<String>) {
        tracing::info!("Span event: {}", name);
    }

    fn add_link(&mut self, _link: String) {}

    fn set_status(&mut self, _status: String) {}

    fn set_attribute(&mut self, attribute: String) {
        tracing::info!("Span attribute: {}", attribute);
    }

    fn end_with_timestamp(&mut self, _timestamp: u64) {
        let duration = self.start_time.elapsed();
        tracing::info!("Finished span: {} (duration: {:?})", self.name, duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_config_default() {
        let config = TraceConfig::default();
        assert!(config.enabled);
        assert_eq!(config.service_name, "fortress");
        assert_eq!(config.sampling.strategy, SamplingStrategy::TraceIdRatio);
        assert_eq!(config.sampling.ratio, 0.1);
    }

    #[test]
    fn test_span_context_empty() {
        let context = SpanContext::empty();
        assert!(context.is_empty());
    }

    #[test]
    fn test_span_context_traceparent() {
        let context = SpanContext {
            trace_id: "1234567890abcdef1234567890abcdef".to_string(),
            span_id: "1234567890abcdef".to_string(),
            parent_span_id: None,
            trace_flags: 1,
            trace_state: String::new(),
            baggage: HashMap::new(),
        };

        let traceparent = context.to_traceparent().unwrap();
        assert!(traceparent.starts_with("00-"));
        
        let parsed = SpanContext::from_traceparent(&traceparent).unwrap();
        assert_eq!(parsed.trace_id, context.trace_id);
        assert_eq!(parsed.span_id, context.span_id);
        assert_eq!(parsed.trace_flags, context.trace_flags);
    }

    #[tokio::test]
    async fn test_observability_tracer_creation() {
        let config = TraceConfig::default();
        let tracer = ObservabilityTracer::new(config);
        assert!(tracer.is_ok());
    }

    #[tokio::test]
    async fn test_span_lifecycle() {
        let config = TraceConfig::default();
        let tracer = ObservabilityTracer::new(config).unwrap();

        let context = tracer
            .start_span("test_operation", None, HashMap::new())
            .await
            .unwrap();

        assert!(!context.is_empty());

        tracer.finish_span(&context, Some("success"), None).await.unwrap();
    }
}
