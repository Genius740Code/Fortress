//! Dashboard management system for Fortress
//!
//! Provides comprehensive dashboard capabilities with widgets,
//! real-time data visualization, and monitoring dashboards.

use crate::error::{FortressError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Dashboard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// Enable dashboard system
    pub enabled: bool,
    /// Dashboard refresh interval in seconds
    pub refresh_interval_seconds: u64,
    /// Maximum number of dashboards
    pub max_dashboards: usize,
    /// Widget configuration
    pub widgets: WidgetConfig,
    /// Theme configuration
    pub theme: ThemeConfig,
    /// Export configuration
    pub export: DashboardExportConfig,
}

/// Widget configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetConfig {
    /// Maximum widgets per dashboard
    pub max_widgets_per_dashboard: usize,
    /// Default widget size
    pub default_size: WidgetSize,
    /// Grid configuration
    pub grid: GridConfig,
    /// Data retention period in hours
    pub data_retention_hours: u32,
}

/// Widget size
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetSize {
    /// Width in grid units
    pub width: u32,
    /// Height in grid units
    pub height: u32,
}

/// Grid configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GridConfig {
    /// Number of columns
    pub columns: u32,
    /// Number of rows
    pub rows: u32,
    /// Gap between widgets in pixels
    pub gap: u32,
}

/// Theme configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemeConfig {
    /// Theme name
    pub name: String,
    /// Color scheme
    pub colors: ColorScheme,
    /// Typography
    pub typography: TypographyConfig,
}

/// Color scheme
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorScheme {
    /// Primary color
    pub primary: String,
    /// Secondary color
    pub secondary: String,
    /// Success color
    pub success: String,
    /// Warning color
    pub warning: String,
    /// Error color
    pub error: String,
    /// Background color
    pub background: String,
    /// Text color
    pub text: String,
}

/// Typography configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypographyConfig {
    /// Font family
    pub font_family: String,
    /// Font size
    pub font_size: u32,
    /// Font weight
    pub font_weight: String,
}

/// Dashboard export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardExportConfig {
    /// Enable export
    pub enabled: bool,
    /// Export formats
    pub formats: Vec<ExportFormat>,
    /// Export interval in seconds
    pub interval_seconds: u64,
    /// Export destination
    pub destination: ExportDestination,
}

/// Export formats
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ExportFormat {
    /// JSON format
    Json,
    /// CSV format
    Csv,
    /// PNG image
    Png,
    /// PDF document
    Pdf,
    /// HTML page
    Html,
}

/// Export destination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportDestination {
    /// Destination type
    pub destination_type: DestinationType,
    /// Destination configuration
    pub config: HashMap<String, String>,
}

/// Destination types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DestinationType {
    /// Local file system
    Local,
    /// S3 bucket
    S3,
    /// HTTP endpoint
    Http,
    /// Email
    Email,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            refresh_interval_seconds: 30,
            max_dashboards: 50,
            widgets: WidgetConfig::default(),
            theme: ThemeConfig::default(),
            export: DashboardExportConfig::default(),
        }
    }
}

impl Default for WidgetConfig {
    fn default() -> Self {
        Self {
            max_widgets_per_dashboard: 20,
            default_size: WidgetSize { width: 4, height: 3 },
            grid: GridConfig { columns: 12, rows: 8, gap: 16 },
            data_retention_hours: 24,
        }
    }
}

impl Default for GridConfig {
    fn default() -> Self {
        Self {
            columns: 12,
            rows: 8,
            gap: 16,
        }
    }
}

impl Default for ThemeConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            colors: ColorScheme::default(),
            typography: TypographyConfig::default(),
        }
    }
}

impl Default for ColorScheme {
    fn default() -> Self {
        Self {
            primary: "#007bff".to_string(),
            secondary: "#6c757d".to_string(),
            success: "#28a745".to_string(),
            warning: "#ffc107".to_string(),
            error: "#dc3545".to_string(),
            background: "#ffffff".to_string(),
            text: "#333333".to_string(),
        }
    }
}

impl Default for TypographyConfig {
    fn default() -> Self {
        Self {
            font_family: "Arial, sans-serif".to_string(),
            font_size: 14,
            font_weight: "normal".to_string(),
        }
    }
}

impl Default for DashboardExportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            formats: vec![ExportFormat::Json],
            interval_seconds: 3600, // 1 hour
            destination: ExportDestination {
                destination_type: DestinationType::Local,
                config: HashMap::new(),
            },
        }
    }
}

/// Dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dashboard {
    /// Dashboard ID
    pub id: String,
    /// Dashboard name
    pub name: String,
    /// Dashboard description
    pub description: String,
    /// Dashboard tags
    pub tags: Vec<String>,
    /// Dashboard widgets
    pub widgets: Vec<Widget>,
    /// Dashboard layout
    pub layout: DashboardLayout,
    /// Dashboard configuration
    pub config: DashboardConfig,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last updated timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Owner
    pub owner: String,
    /// Access permissions
    pub permissions: DashboardPermissions,
}

/// Dashboard layout
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardLayout {
    /// Layout type
    pub layout_type: LayoutType,
    /// Grid configuration
    pub grid: GridConfig,
    /// Widget positions
    pub widget_positions: HashMap<String, WidgetPosition>,
}

/// Layout types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LayoutType {
    /// Grid layout
    Grid,
    /// Free-form layout
    Free,
    /// Tabbed layout
    Tabbed,
}

/// Widget position
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetPosition {
    /// X position
    pub x: u32,
    /// Y position
    pub y: u32,
    /// Width
    pub width: u32,
    /// Height
    pub height: u32,
}

/// Dashboard permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardPermissions {
    /// Public visibility
    pub public: bool,
    /// Allowed users
    pub allowed_users: Vec<String>,
    /// Allowed roles
    pub allowed_roles: Vec<String>,
}

/// Widget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Widget {
    /// Widget ID
    pub id: String,
    /// Widget type
    pub widget_type: WidgetType,
    /// Widget title
    pub title: String,
    /// Widget configuration
    pub config: WidgetConfigData,
    /// Widget data source
    pub data_source: DataSource,
    /// Widget position
    pub position: WidgetPosition,
    /// Widget size
    pub size: WidgetSize,
    /// Widget refresh interval in seconds
    pub refresh_interval_seconds: u64,
    /// Widget enabled status
    pub enabled: bool,
}

/// Widget types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum WidgetType {
    /// Metric chart
    MetricChart,
    /// Time series chart
    TimeSeriesChart,
    /// Gauge chart
    GaugeChart,
    /// Table widget
    Table,
    /// Text widget
    Text,
    /// Alert widget
    AlertList,
    /// Health status widget
    HealthStatus,
    /// Log viewer widget
    LogViewer,
    /// System info widget
    SystemInfo,
}

/// Widget configuration data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetConfigData {
    /// Widget-specific configuration
    pub config: HashMap<String, serde_json::Value>,
    /// Visualization settings
    pub visualization: VisualizationConfig,
}

/// Visualization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualizationConfig {
    /// Chart type
    pub chart_type: Option<ChartType>,
    /// Color scheme
    pub color_scheme: Option<String>,
    /// Axis configuration
    pub axes: Option<AxisConfig>,
    /// Legend configuration
    pub legend: Option<LegendConfig>,
}

/// Chart types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ChartType {
    /// Line chart
    Line,
    /// Bar chart
    Bar,
    /// Pie chart
    Pie,
    /// Area chart
    Area,
    /// Scatter plot
    Scatter,
    /// Heatmap
    Heatmap,
}

/// Axis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxisConfig {
    /// X-axis configuration
    pub x_axis: Option<Axis>,
    /// Y-axis configuration
    pub y_axis: Option<Axis>,
}

/// Axis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Axis {
    /// Axis label
    pub label: String,
    /// Axis type
    pub axis_type: AxisType,
    /// Minimum value
    pub min: Option<f64>,
    /// Maximum value
    pub max: Option<f64>,
}

/// Axis types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AxisType {
    /// Linear axis
    Linear,
    /// Logarithmic axis
    Logarithmic,
    /// Time axis
    Time,
    /// Category axis
    Category,
}

/// Legend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegendConfig {
    /// Show legend
    pub show: bool,
    /// Legend position
    pub position: LegendPosition,
}

/// Legend positions
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LegendPosition {
    /// Top position
    Top,
    /// Bottom position
    Bottom,
    /// Left position
    Left,
    /// Right position
    Right,
}

/// Data source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSource {
    /// Data source type
    pub source_type: DataSourceType,
    /// Data source configuration
    pub config: HashMap<String, String>,
    /// Query or metric name
    pub query: String,
    /// Refresh interval in seconds
    pub refresh_interval_seconds: u64,
}

/// Data source types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DataSourceType {
    /// Metrics data source
    Metrics,
    /// Logs data source
    Logs,
    /// Traces data source
    Traces,
    /// Health checks data source
    Health,
    /// Alerts data source
    Alerts,
    /// Time series data source
    TimeSeries,
    /// Custom data source
    Custom,
}

/// Dashboard manager
pub struct DashboardManager {
    /// Configuration
    config: DashboardConfig,
    /// Dashboards
    dashboards: Arc<RwLock<HashMap<String, Dashboard>>>,
    /// Widget data cache
    widget_data: Arc<RwLock<HashMap<String, WidgetData>>>,
    /// Data providers
    data_providers: std::collections::HashMap<DataSourceType, Box<dyn DataProvider + Send + Sync>>,
}

/// Widget data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WidgetData {
    /// Widget ID
    pub widget_id: String,
    /// Data timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Data content
    pub data: WidgetDataContent,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// Widget data content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WidgetDataContent {
    /// Time series data
    TimeSeries(Vec<TimeSeriesPoint>),
    /// Metric value
    Metric(f64),
    /// Table data
    Table(TableData),
    /// Alert list
    AlertList(Vec<AlertInfo>),
    /// Health status
    HealthStatus(HealthInfo),
    /// Log entries
    LogEntries(Vec<LogEntry>),
    /// System information
    SystemInfo(SystemInfoData),
    /// Text content
    Text(String),
    /// JSON data
    Json(serde_json::Value),
}

/// Time series point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Value
    pub value: f64,
    /// Labels
    pub labels: HashMap<String, String>,
}

/// Table data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableData {
    /// Column names
    pub columns: Vec<String>,
    /// Rows
    pub rows: Vec<Vec<serde_json::Value>>,
}

/// Alert information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertInfo {
    /// Alert ID
    pub id: String,
    /// Alert title
    pub title: String,
    /// Alert severity
    pub severity: String,
    /// Alert status
    pub status: String,
    /// Creation time
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthInfo {
    /// Overall status
    pub status: String,
    /// Component health
    pub components: HashMap<String, ComponentHealthInfo>,
}

/// Component health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealthInfo {
    /// Component name
    pub name: String,
    /// Health status
    pub status: String,
    /// Last check time
    pub last_check: chrono::DateTime<chrono::Utc>,
    /// Response time in milliseconds
    pub response_time_ms: u64,
}

/// Log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Log level
    pub level: String,
    /// Message
    pub message: String,
    /// Source
    pub source: String,
}

/// System information data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfoData {
    /// CPU usage percentage
    pub cpu_usage_percent: f64,
    /// Memory usage percentage
    pub memory_usage_percent: f64,
    /// Disk usage percentage
    pub disk_usage_percent: f64,
    /// Network I/O
    pub network_io: NetworkIoData,
    /// Uptime in seconds
    pub uptime_seconds: u64,
}

/// Network I/O data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIoData {
    /// Bytes received
    pub bytes_received: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Packets sent
    pub packets_sent: u64,
}

/// Data provider trait
#[async_trait::async_trait]
pub trait DataProvider: Send + Sync {
    /// Get data for a widget
    async fn get_data(&self, widget: &Widget) -> Result<WidgetData>;
}

impl DashboardManager {
    /// Create a new dashboard manager
    pub fn new(config: DashboardConfig) -> Self {
        Self {
            config,
            dashboards: Arc::new(RwLock::new(HashMap::new())),
            widget_data: Arc::new(RwLock::new(HashMap::new())),
            data_providers: std::collections::HashMap::new(),
        }
    }

    /// Register a data provider
    pub fn register_data_provider(&mut self, source_type: DataSourceType, provider: Box<dyn DataProvider + Send + Sync>) {
        self.data_providers.insert(source_type, provider);
    }

    /// Create a new dashboard
    pub async fn create_dashboard(&self, dashboard: Dashboard) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut dashboards = self.dashboards.write().await;
        
        if dashboards.len() >= self.config.max_dashboards {
            return Err(FortressError::validation("Maximum number of dashboards reached".to_string(), None, None));
        }

        if dashboards.contains_key(&dashboard.id) {
            return Err(FortressError::validation(
                format!("Dashboard '{}' already exists", dashboard.id),
                None,
                None,
            ));
        }

        dashboards.insert(dashboard.id.clone(), dashboard.clone());
        tracing::info!("Created dashboard: {}", dashboard.id);

        Ok(())
    }

    /// Update a dashboard
    pub async fn update_dashboard(&self, dashboard: Dashboard) -> Result<()> {
        let mut dashboards = self.dashboards.write().await;
        
        if !dashboards.contains_key(&dashboard.id) {
            return Err(FortressError::validation(
                format!("Dashboard '{}' not found", dashboard.id),
                None,
                None,
            ));
        }

        let mut updated_dashboard = dashboard.clone();
        updated_dashboard.updated_at = chrono::Utc::now();
        
        dashboards.insert(dashboard.id.clone(), updated_dashboard);
        tracing::info!("Updated dashboard: {}", dashboard.id);

        Ok(())
    }

    /// Delete a dashboard
    pub async fn delete_dashboard(&self, dashboard_id: &str) -> Result<()> {
        let mut dashboards = self.dashboards.write().await;
        
        if dashboards.remove(dashboard_id).is_none() {
            return Err(FortressError::validation(
                format!("Dashboard '{}' not found", dashboard_id),
                None,
                None,
            ));
        }

        // Clean up widget data
        let mut widget_data = self.widget_data.write().await;
        widget_data.retain(|_, _data| {
            // This would need to check if the data belongs to the deleted dashboard
            true // For now, keep all data
        });

        tracing::info!("Deleted dashboard: {}", dashboard_id);
        Ok(())
    }

    /// Get a dashboard
    pub async fn get_dashboard(&self, dashboard_id: &str) -> Result<Option<Dashboard>> {
        let dashboards = self.dashboards.read().await;
        Ok(dashboards.get(dashboard_id).cloned())
    }

    /// List all dashboards
    pub async fn list_dashboards(&self) -> Vec<Dashboard> {
        let dashboards = self.dashboards.read().await;
        dashboards.values().cloned().collect()
    }

    /// Get widget data
    pub async fn get_widget_data(&self, widget_id: &str) -> Result<Option<WidgetData>> {
        let widget_data = self.widget_data.read().await;
        Ok(widget_data.get(widget_id).cloned())
    }

    /// Refresh widget data
    pub async fn refresh_widget_data(&self, widget: &Widget) -> Result<WidgetData> {
        if !self.config.enabled {
            return Err(FortressError::validation("Dashboard system is disabled".to_string(), None, None));
        }

        let provider = self.data_providers.get(&widget.data_source.source_type)
            .ok_or_else(|| FortressError::validation(
                format!("No data provider for source type: {:?}", widget.data_source.source_type),
                None,
                None,
            ))?;

        let data = provider.get_data(widget).await?;

        // Cache the data
        let mut widget_data = self.widget_data.write().await;
        widget_data.insert(widget.id.clone(), data.clone());

        Ok(data)
    }

    /// Refresh all widgets in a dashboard
    pub async fn refresh_dashboard(&self, dashboard_id: &str) -> Result<Vec<WidgetData>> {
        let dashboards = self.dashboards.read().await;
        let dashboard = dashboards.get(dashboard_id)
            .ok_or_else(|| FortressError::validation(
                format!("Dashboard '{}' not found", dashboard_id),
                None,
                None,
            ))?;

        let mut widget_data_list = Vec::new();

        for widget in &dashboard.widgets {
            if widget.enabled {
                match self.refresh_widget_data(widget).await {
                    Ok(data) => widget_data_list.push(data),
                    Err(e) => tracing::error!("Failed to refresh widget {}: {}", widget.id, e),
                }
            }
        }

        Ok(widget_data_list)
    }

    /// Export dashboard
    pub async fn export_dashboard(&self, dashboard_id: &str, format: ExportFormat) -> Result<Vec<u8>> {
        let dashboard = self.get_dashboard(dashboard_id).await?
            .ok_or_else(|| FortressError::validation(
                format!("Dashboard '{}' not found", dashboard_id),
                None,
                None,
            ))?;

        match format {
            ExportFormat::Json => {
                let json = serde_json::to_vec_pretty(&dashboard)?;
                Ok(json)
            }
            ExportFormat::Csv => {
                // Export widget data as CSV
                let widget_data = self.refresh_dashboard(dashboard_id).await?;
                let mut csv_content = Vec::new();
                
                for data in widget_data {
                    match data.data {
                        WidgetDataContent::TimeSeries(points) => {
                            csv_content.extend_from_slice(b"timestamp,value\n");
                            for point in points {
                                csv_content.extend_from_slice(format!("{},{}\n", point.timestamp, point.value).as_bytes());
                            }
                        }
                        _ => {
                            // Handle other data types
                        }
                    }
                }
                
                Ok(csv_content)
            }
            ExportFormat::Html => {
                let html = self.generate_html_dashboard(&dashboard).await?;
                Ok(html.into_bytes())
            }
            ExportFormat::Png | ExportFormat::Pdf => {
                // Would require additional libraries for image/PDF generation
                Err(FortressError::validation(
                    format!("Export format {:?} not yet implemented", format),
                    None,
                    None,
                ))
            }
        }
    }

    /// Generate HTML dashboard
    async fn generate_html_dashboard(&self, dashboard: &Dashboard) -> Result<String> {
        let html = format!(
            r#"
<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .dashboard {{ max-width: 1200px; margin: 0 auto; }}
        .widget {{ border: 1px solid #ddd; margin: 10px; padding: 10px; }}
        .widget-title {{ font-weight: bold; margin-bottom: 10px; }}
    </style>
</head>
<body>
    <div class="dashboard">
        <h1>{title}</h1>
        <p>{description}</p>
        {widgets}
    </div>
</body>
</html>
            "#,
            title = dashboard.name,
            description = dashboard.description,
            widgets = dashboard.widgets.iter().map(|w| format!(
                r#"<div class="widget">
                    <div class="widget-title">{title}</div>
                    <div>Widget data would be rendered here</div>
                </div>"#,
                title = w.title
            )).collect::<Vec<_>>().join("\n")
        );

        Ok(html)
    }

    /// Start the dashboard manager
    pub async fn start(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Start background refresh task
        self.start_refresh_task().await;

        tracing::info!("Dashboard manager started");
        Ok(())
    }

    /// Shutdown the dashboard manager
    pub async fn shutdown(&self) -> Result<()> {
        if self.config.enabled {
            tracing::info!("Dashboard manager shutdown");
        }
        Ok(())
    }

    /// Start background refresh task
    async fn start_refresh_task(&self) {
        let dashboard_manager = self.clone();
        let interval = Duration::from_secs(self.config.refresh_interval_seconds);

        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            
            loop {
                timer.tick().await;
                
                let dashboards = dashboard_manager.list_dashboards().await;
                for dashboard in dashboards {
                    if let Err(e) = dashboard_manager.refresh_dashboard(&dashboard.id).await {
                        tracing::error!("Failed to refresh dashboard {}: {}", dashboard.id, e);
                    }
                }
            }
        });
    }
}

impl Clone for DashboardManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            dashboards: self.dashboards.clone(),
            widget_data: self.widget_data.clone(),
            data_providers: HashMap::new(), // Data providers are not cloned
        }
    }
}

/// Mock data provider for testing
pub struct MockDataProvider {
    provider_type: DataSourceType,
}

impl MockDataProvider {
    /// Create a new mock data provider
    /// 
    /// # Arguments
    /// * `provider_type` - Type of data source to mock
    pub fn new(provider_type: DataSourceType) -> Self {
        Self { provider_type }
    }
}

#[async_trait::async_trait]
impl DataProvider for MockDataProvider {
    async fn get_data(&self, widget: &Widget) -> Result<WidgetData> {
        let data = match self.provider_type {
            DataSourceType::Metrics => {
                WidgetDataContent::Metric(rand::random::<f64>() * 100.0)
            }
            DataSourceType::TimeSeries => {
                let points = vec![
                    TimeSeriesPoint {
                        timestamp: chrono::Utc::now() - chrono::Duration::minutes(5),
                        value: rand::random::<f64>() * 100.0,
                        labels: HashMap::new(),
                    },
                    TimeSeriesPoint {
                        timestamp: chrono::Utc::now() - chrono::Duration::minutes(4),
                        value: rand::random::<f64>() * 100.0,
                        labels: HashMap::new(),
                    },
                    TimeSeriesPoint {
                        timestamp: chrono::Utc::now() - chrono::Duration::minutes(3),
                        value: rand::random::<f64>() * 100.0,
                        labels: HashMap::new(),
                    },
                ];
                WidgetDataContent::TimeSeries(points)
            }
            DataSourceType::Health => {
                let mut components = HashMap::new();
                components.insert("database".to_string(), ComponentHealthInfo {
                    name: "database".to_string(),
                    status: "healthy".to_string(),
                    last_check: chrono::Utc::now(),
                    response_time_ms: 50,
                });
                
                WidgetDataContent::HealthStatus(HealthInfo {
                    status: "healthy".to_string(),
                    components,
                })
            }
            _ => WidgetDataContent::Text("Mock data".to_string()),
        };

        Ok(WidgetData {
            widget_id: widget.id.clone(),
            timestamp: chrono::Utc::now(),
            data,
            metadata: HashMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dashboard_manager_creation() {
        let config = DashboardConfig::default();
        let manager = DashboardManager::new(config);
        assert!(manager.config.enabled);
    }

    #[tokio::test]
    async fn test_dashboard_crud() {
        let config = DashboardConfig::default();
        let manager = DashboardManager::new(config);

        let dashboard = Dashboard {
            id: "test_dashboard".to_string(),
            name: "Test Dashboard".to_string(),
            description: "A test dashboard".to_string(),
            tags: vec!["test".to_string()],
            widgets: Vec::new(),
            layout: DashboardLayout {
                layout_type: LayoutType::Grid,
                grid: GridConfig::default(),
                widget_positions: HashMap::new(),
            },
            config: DashboardConfig::default(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            owner: "test_user".to_string(),
            permissions: DashboardPermissions {
                public: true,
                allowed_users: Vec::new(),
                allowed_roles: Vec::new(),
            },
        };

        // Create
        manager.create_dashboard(dashboard.clone()).await.unwrap();
        
        // Read
        let retrieved = manager.get_dashboard("test_dashboard").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test Dashboard");

        // List
        let dashboards = manager.list_dashboards().await;
        assert_eq!(dashboards.len(), 1);

        // Update
        let mut updated_dashboard = dashboard;
        updated_dashboard.name = "Updated Test Dashboard".to_string();
        manager.update_dashboard(updated_dashboard).await.unwrap();

        // Delete
        manager.delete_dashboard("test_dashboard").await.unwrap();
        
        let dashboards = manager.list_dashboards().await;
        assert_eq!(dashboards.len(), 0);
    }

    #[tokio::test]
    async fn test_widget_data_refresh() {
        let config = DashboardConfig::default();
        let mut manager = DashboardManager::new(config);
        
        // Register mock data provider
        manager.register_data_provider(DataSourceType::Metrics, Box::new(MockDataProvider::new(DataSourceType::Metrics)));

        let widget = Widget {
            id: "test_widget".to_string(),
            widget_type: WidgetType::MetricChart,
            title: "Test Widget".to_string(),
            config: WidgetConfigData {
                config: HashMap::new(),
                visualization: VisualizationConfig {
                    chart_type: Some(ChartType::Line),
                    color_scheme: None,
                    axes: None,
                    legend: None,
                },
            },
            data_source: DataSource {
                source_type: DataSourceType::Metrics,
                config: HashMap::new(),
                query: "test_metric".to_string(),
                refresh_interval_seconds: 60,
            },
            position: WidgetPosition { x: 0, y: 0, width: 4, height: 3 },
            size: WidgetSize { width: 4, height: 3 },
            refresh_interval_seconds: 60,
            enabled: true,
        };

        let data = manager.refresh_widget_data(&widget).await.unwrap();
        assert!(matches!(data.data, WidgetDataContent::Metric(_)));
    }
}
