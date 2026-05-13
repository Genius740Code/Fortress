//! Automatic performance tuning system for Fortress

//!

//! This module provides intelligent automatic performance tuning that

//! continuously optimizes system parameters based on real-time metrics.



use crate::error::{FortressError, Result};

use crate::performance_monitor::{AdvancedPerformanceMonitor as PerformanceMonitor, RecommendationType as PmRecommendationType, ImplementationComplexity as PmImplementationComplexity, RecommendationPriority as PmRecommendationPriority};

use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use std::sync::Arc;

use std::time::Duration;

use tokio::sync::RwLock;

use uuid::Uuid;



/// Auto-tuning configuration

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct AutoTuningConfig {

    /// Enable automatic tuning

    pub enabled: bool,

    /// Tuning interval in seconds

    pub tuning_interval_seconds: u64,

    /// Minimum confidence threshold for applying changes

    pub min_confidence_threshold: f64,

    /// Maximum change percentage per tuning cycle

    pub max_change_percentage: f64,

    /// Enable gradual changes (ramp up slowly)

    pub enable_gradual_changes: bool,

    /// Safety mode (more conservative changes)

    pub safety_mode: bool,

    /// Require approval for high-impact changes

    pub require_approval_for_high_impact: bool,

    /// Rollback automatically on performance degradation

    pub enable_auto_rollback: bool,

    /// Performance degradation threshold for rollback

    pub rollback_threshold_percent: f64,

    /// Minimum observation period after changes

    pub observation_period_minutes: u32,

}



impl Default for AutoTuningConfig {

    fn default() -> Self {

        Self {

            enabled: true,

            tuning_interval_seconds: 300, // 5 minutes

            min_confidence_threshold: 0.7,

            max_change_percentage: 0.25, // 25% max change

            enable_gradual_changes: true,

            safety_mode: true,

            require_approval_for_high_impact: true,

            enable_auto_rollback: true,

            rollback_threshold_percent: 10.0,

            observation_period_minutes: 10,

        }

    }

}



/// Tuning parameter definition

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct TuningParameter {

    /// Parameter name

    pub name: String,

    /// Current value

    pub current_value: serde_json::Value,

    /// Data type

    pub data_type: ParameterType,

    /// Minimum allowed value

    pub min_value: Option<serde_json::Value>,

    /// Maximum allowed value

    pub max_value: Option<serde_json::Value>,

    /// Step size for adjustments

    pub step_size: Option<serde_json::Value>,

    /// Parameter category

    pub category: ParameterCategory,

    /// Impact level

    pub impact_level: ImpactLevel,

    /// Requires restart to apply

    pub requires_restart: bool,

    /// Description

    pub description: String,

}



/// Parameter data types

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]

pub enum ParameterType {

    /// Integer value

    Integer,

    /// Floating point value

    Float,

    /// Boolean value

    Boolean,

    /// String value

    String,

    /// Duration in seconds

    DurationSeconds,

    /// Size in bytes

    SizeBytes,

    /// Percentage (0.0 to 1.0)

    Percentage,

}



/// Parameter categories

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]

pub enum ParameterCategory {

    /// Cache parameters

    Cache,

    /// Connection pool parameters

    ConnectionPool,

    /// Database parameters

    Database,

    /// Memory parameters

    Memory,

    /// CPU parameters

    CPU,

    /// Network parameters

    Network,

    /// Security parameters

    Security,

    /// Performance parameters

    Performance,

}



/// Impact levels for parameter changes

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]

pub enum ImpactLevel {

    /// Low impact (safe to change)

    Low,

    /// Medium impact (requires testing)

    Medium,

    /// High impact (requires careful consideration)

    High,

    /// Critical impact (could affect stability)

    Critical,

}






/// Change status

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]

pub enum ChangeStatus {

    /// Change is being applied

    Applying,

    /// Change has been applied

    Applied,

    /// Change is being observed

    Observing,

    /// Change was successful

    Successful,

    /// Change failed

    Failed,

    /// Change was rolled back

    RolledBack,

    /// Change requires approval

    PendingApproval,

}



/// Rollback information

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct RollbackInfo {

    /// Reason for rollback

    pub reason: String,

    /// Timestamp when rollback was initiated

    pub rollback_at: chrono::DateTime<chrono::Utc>,

    /// Performance degradation observed

    pub degradation_percent: f64,

}



/// Tuning strategy

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct TuningStrategy {

    /// Strategy name

    pub name: String,

    /// Strategy description

    pub description: String,

    /// Target parameters

    pub target_parameters: Vec<String>,

    /// Optimization goal

    pub optimization_goal: OptimizationGoal,

    /// Priority

    pub priority: u8,

    /// Enabled

    pub enabled: bool,

}



/// Optimization goals

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]

pub enum OptimizationGoal {

    /// Minimize response time

    MinimizeResponseTime,

    /// Maximize throughput

    MaximizeThroughput,

    /// Minimize memory usage

    MinimizeMemoryUsage,

    /// Minimize CPU usage

    MinimizeCpuUsage,

    /// Maximize cache hit ratio

    MaximizeCacheHitRatio,

    /// Balance all metrics

    BalanceAll,

}



/// Automatic performance tuner

#[derive(Debug)]

pub struct AutomaticPerformanceTuner {

    /// Configuration

    config: AutoTuningConfig,

    /// Performance monitor

    performance_monitor: Arc<PerformanceMonitor>,

    /// Tunable parameters

    parameters: Arc<RwLock<HashMap<String, TuningParameter>>>,

    /// Applied changes history

    applied_changes: Arc<RwLock<Vec<AppliedChange>>>,

    /// Active tuning strategies

    strategies: Arc<RwLock<Vec<TuningStrategy>>>,

    /// Current system state

    system_state: Arc<RwLock<SystemState>>,

}






impl AutomaticPerformanceTuner {

    /// Create a new automatic performance tuner

    pub async fn new(

        config: AutoTuningConfig,

        performance_monitor: Arc<PerformanceMonitor>,

    ) -> Self {

        let tuner = Self {

            config,

            performance_monitor,

            parameters: Arc::new(RwLock::new(HashMap::new())),

            applied_changes: Arc::new(RwLock::new(Vec::new())),

            strategies: Arc::new(RwLock::new(Vec::new())),

            system_state: Arc::new(RwLock::new(SystemState {

                performance_metrics: HashMap::new(),

                system_load: 0.0,

                active_connections: 0,

                memory_usage_percent: 0.0,

                cpu_usage_percent: 0.0,

                cache_hit_ratio: 0.0,

                error_rate: 0.0,

                last_updated: chrono::Utc::now(),

            })),

        };



        // Initialize default parameters

        tuner.initialize_default_parameters().await;



        // Initialize default strategies

        tuner.initialize_default_strategies().await;



        // Start background tuning task

        if tuner.config.enabled {

            tuner.start_tuning_task();

        }



        tuner

    }



    /// Initialize default tunable parameters

    async fn initialize_default_parameters(&self) {

        let mut params = self.parameters.write().await;

        

        // Cache parameters

        params.insert("cache_size".to_string(), TuningParameter {

            name: "cache_size".to_string(),

            current_value: serde_json::Value::Number(serde_json::Number::from(1000)),

            data_type: ParameterType::Integer,

            min_value: Some(serde_json::Value::Number(serde_json::Number::from(100))),

            max_value: Some(serde_json::Value::Number(serde_json::Number::from(10000))),

            step_size: Some(serde_json::Value::Number(serde_json::Number::from(100))),

            category: ParameterCategory::Cache,

            impact_level: ImpactLevel::Medium,

            requires_restart: false,

            description: "Maximum number of entries in cache".to_string(),

        });



        params.insert("cache_ttl_seconds".to_string(), TuningParameter {

            name: "cache_ttl_seconds".to_string(),

            current_value: serde_json::Value::Number(serde_json::Number::from(3600)),

            data_type: ParameterType::DurationSeconds,

            min_value: Some(serde_json::Value::Number(serde_json::Number::from(60))),

            max_value: Some(serde_json::Value::Number(serde_json::Number::from(86400))),

            step_size: Some(serde_json::Value::Number(serde_json::Number::from(300))),

            category: ParameterCategory::Cache,

            impact_level: ImpactLevel::Low,

            requires_restart: false,

            description: "Time-to-live for cache entries in seconds".to_string(),

        });



        // Connection pool parameters

        params.insert("max_connections".to_string(), TuningParameter {

            name: "max_connections".to_string(),

            current_value: serde_json::Value::Number(serde_json::Number::from(100)),

            data_type: ParameterType::Integer,

            min_value: Some(serde_json::Value::Number(serde_json::Number::from(10))),

            max_value: Some(serde_json::Value::Number(serde_json::Number::from(1000))),

            step_size: Some(serde_json::Value::Number(serde_json::Number::from(10))),

            category: ParameterCategory::ConnectionPool,

            impact_level: ImpactLevel::Medium,

            requires_restart: false,

            description: "Maximum number of connections in pool".to_string(),

        });



        params.insert("connection_timeout_seconds".to_string(), TuningParameter {

            name: "connection_timeout_seconds".to_string(),

            current_value: serde_json::Value::Number(serde_json::Number::from(30)),

            data_type: ParameterType::DurationSeconds,

            min_value: Some(serde_json::Value::Number(serde_json::Number::from(5))),

            max_value: Some(serde_json::Value::Number(serde_json::Number::from(300))),

            step_size: Some(serde_json::Value::Number(serde_json::Number::from(5))),

            category: ParameterCategory::ConnectionPool,

            impact_level: ImpactLevel::Low,

            requires_restart: false,

            description: "Connection timeout in seconds".to_string(),

        });



        // Database parameters

        params.insert("db_query_timeout_seconds".to_string(), TuningParameter {

            name: "db_query_timeout_seconds".to_string(),

            current_value: serde_json::Value::Number(serde_json::Number::from(60)),

            data_type: ParameterType::DurationSeconds,

            min_value: Some(serde_json::Value::Number(serde_json::Number::from(10))),

            max_value: Some(serde_json::Value::Number(serde_json::Number::from(600))),

            step_size: Some(serde_json::Value::Number(serde_json::Number::from(10))),

            category: ParameterCategory::Database,

            impact_level: ImpactLevel::Medium,

            requires_restart: false,

            description: "Database query timeout in seconds".to_string(),

        });

    }



    /// Initialize default tuning strategies

    async fn initialize_default_strategies(&self) {

        let mut strategies = self.strategies.write().await;

        

        strategies.push(TuningStrategy {

            name: "optimize_cache_performance".to_string(),

            description: "Optimize cache parameters for better hit ratio".to_string(),

            target_parameters: vec!["cache_size".to_string(), "cache_ttl_seconds".to_string()],

            optimization_goal: OptimizationGoal::MaximizeCacheHitRatio,

            priority: 1,

            enabled: true,

        });



        strategies.push(TuningStrategy {

            name: "optimize_connection_pool".to_string(),

            description: "Optimize connection pool for better throughput".to_string(),

            target_parameters: vec!["max_connections".to_string(), "connection_timeout_seconds".to_string()],

            optimization_goal: OptimizationGoal::MaximizeThroughput,

            priority: 2,

            enabled: true,

        });



        strategies.push(TuningStrategy {

            name: "optimize_response_time".to_string(),

            description: "Reduce response times across all operations".to_string(),

            target_parameters: vec![

                "cache_size".to_string(),

                "max_connections".to_string(),

                "db_query_timeout_seconds".to_string(),

            ],

            optimization_goal: OptimizationGoal::MinimizeResponseTime,

            priority: 3,

            enabled: true,

        });

    }



    /// Start background tuning task

    fn start_tuning_task(&self) {

        let performance_monitor = self.performance_monitor.clone();

        let parameters = self.parameters.clone();

        let applied_changes = self.applied_changes.clone();

        let strategies = self.strategies.clone();

        let system_state = self.system_state.clone();

        let config = self.config.clone();

        let interval = Duration::from_secs(config.tuning_interval_seconds);



        tokio::spawn(async move {

            let mut interval_timer = tokio::time::interval(interval);

            

            loop {

                interval_timer.tick().await;

                

                if let Err(e) = Self::perform_tuning_cycle(

                    &performance_monitor,

                    &parameters,

                    &applied_changes,

                    &strategies,

                    &system_state,

                    &config,

                ).await {

                    eprintln!("Auto-tuning cycle failed: {}", e);

                }

            }

        });

    }



    /// Perform a complete tuning cycle

    async fn perform_tuning_cycle(

        performance_monitor: &Arc<PerformanceMonitor>,

        parameters: &Arc<RwLock<HashMap<String, TuningParameter>>>,

        applied_changes: &Arc<RwLock<Vec<AppliedChange>>>,

        strategies: &Arc<RwLock<Vec<TuningStrategy>>>,

        system_state: &Arc<RwLock<SystemState>>,

        config: &AutoTuningConfig,

    ) -> Result<()> {

        // Update system state

        Self::update_system_state(performance_monitor, system_state).await?;



        // Check for rollbacks needed

        Self::check_for_rollbacks(applied_changes, system_state, config).await?;



        // Get current recommendations

        let pm_recommendations = performance_monitor.get_recommendations().await?;

        // Convert to auto_tuning::TuningRecommendation

        let recommendations: Vec<TuningRecommendation> = pm_recommendations.into_iter().map(|pm_rec| {

            // Map the recommendation type

            let recommendation_type = match pm_rec.recommendation_type {

                PmRecommendationType::IncreaseCacheSize => RecommendationType::IncreaseCacheSize,

                PmRecommendationType::AdjustConnectionPool => RecommendationType::AdjustConnectionPool,

                PmRecommendationType::OptimizeQueries => RecommendationType::IncreaseCacheSize, // Map to closest

                _ => RecommendationType::IncreaseCacheSize, // Default

            };

            // Map complexity

            let complexity = match pm_rec.complexity {

                PmImplementationComplexity::Low => ImplementationComplexity::Low,

                PmImplementationComplexity::Medium => ImplementationComplexity::Medium,

                PmImplementationComplexity::High => ImplementationComplexity::High,

            };

            // Map priority

            let priority = match pm_rec.priority {

                PmRecommendationPriority::Low => RecommendationPriority::Low,

                PmRecommendationPriority::Medium => RecommendationPriority::Medium,

                PmRecommendationPriority::High => RecommendationPriority::High,

                PmRecommendationPriority::Critical => RecommendationPriority::Critical,

            };

            TuningRecommendation {

                id: pm_rec.id,

                recommendation_type,

                description: pm_rec.description,

                expected_improvement: pm_rec.expected_improvement,

                complexity,

                priority,

                parameters: pm_rec.parameters,

            }

        }).collect();

        

        // Get active strategies

        let strategies_guard = strategies.read().await;

        let active_strategies: Vec<&TuningStrategy> = strategies_guard

            .iter()

            .filter(|s| s.enabled)

            .collect();



        // Apply tuning based on strategies and recommendations

        for strategy in active_strategies {

            if let Err(e) = Self::apply_strategy(

                strategy,

                recommendations.as_slice(),

                parameters,

                applied_changes,

                system_state,

                config,

            ).await {

                eprintln!("Failed to apply strategy {}: {}", strategy.name, e);

            }

        }



        // Clean up old applied changes

        Self::cleanup_old_changes(applied_changes, config).await?;



        Ok(())

    }



    /// Update current system state

    async fn update_system_state(

        performance_monitor: &Arc<PerformanceMonitor>,

        system_state: &Arc<RwLock<SystemState>>,

    ) -> Result<()> {

        let metrics = performance_monitor.get_metrics().await?;

        let mut state = system_state.write().await;



        // Extract key metrics from aggregated data

        for (operation_type, aggregated_metrics) in metrics {

            state.performance_metrics.insert(

                format!("avg_response_time_{}", operation_type),

                aggregated_metrics.avg_response_time_ms,

            );

            state.performance_metrics.insert(

                format!("throughput_{}", operation_type),

                aggregated_metrics.throughput,

            );

            state.performance_metrics.insert(

                format!("error_rate_{}", operation_type),

                aggregated_metrics.error_rate_percent,

            );

        }



        // Update system metrics (simplified - would get actual system metrics)

        state.memory_usage_percent = 50.0; // Placeholder

        state.cpu_usage_percent = 30.0; // Placeholder

        state.cache_hit_ratio = 0.8; // Placeholder

        state.error_rate = 1.0; // Placeholder

        state.last_updated = chrono::Utc::now();



        Ok(())

    }



    /// Check if any applied changes need to be rolled back

    async fn check_for_rollbacks(

        applied_changes: &Arc<RwLock<Vec<AppliedChange>>>,

        system_state: &Arc<RwLock<SystemState>>,

        config: &AutoTuningConfig,

    ) -> Result<()> {

        if !config.enable_auto_rollback {

            return Ok(());

        }



        let state = system_state.read().await;

        let mut changes = applied_changes.write().await;



        for change in changes.iter_mut() {

            if change.status == ChangeStatus::Observing {

                // Check if performance has degraded

                let degradation = Self::calculate_performance_degradation(&change.metrics_before, &state.performance_metrics);

                

                if degradation > config.rollback_threshold_percent {

                    // Initiate rollback

                    change.status = ChangeStatus::RolledBack;

                    change.rollback_info = Some(RollbackInfo {

                        reason: format!("Performance degraded by {:.1}%", degradation),

                        rollback_at: chrono::Utc::now(),

                        degradation_percent: degradation,

                    });



                    // Actually rollback the parameter change

                    Self::rollback_parameter_change(change).await?;

                }

            }

        }



        Ok(())

    }



    /// Calculate performance degradation percentage

    fn calculate_performance_degradation(

        before_metrics: &HashMap<String, f64>,

        after_metrics: &HashMap<String, f64>,

    ) -> f64 {

        let mut total_degradation = 0.0;

        let mut metric_count = 0;



        for (metric_name, before_value) in before_metrics {

            if let Some(after_value) = after_metrics.get(metric_name) {

                // For response times, lower is better

                if metric_name.contains("response_time") || metric_name.contains("error_rate") {

                    if *after_value > *before_value {

                        let degradation = ((after_value - before_value) / before_value) * 100.0;

                        total_degradation += degradation;

                        metric_count += 1;

                    }

                }

                // For throughput, higher is better

                else if metric_name.contains("throughput") || metric_name.contains("hit_ratio") {

                    if *after_value < *before_value {

                        let degradation = ((before_value - after_value) / before_value) * 100.0;

                        total_degradation += degradation;

                        metric_count += 1;

                    }

                }

            }

        }



        if metric_count > 0 {

            total_degradation / metric_count as f64

        } else {

            0.0

        }

    }



    /// Rollback a parameter change

    async fn rollback_parameter_change(change: &mut AppliedChange) -> Result<()> {

        // In a real implementation, this would actually revert the parameter

        // For now, we just log the rollback

        println!("Rolling back parameter {} from {:?} to {:?}",

            change.parameter_name,

            change.new_value,

            change.previous_value

        );



        // Update the parameter's current value

        // This would require access to the actual parameter store



        Ok(())

    }



    /// Apply a tuning strategy

    async fn apply_strategy(

        strategy: &TuningStrategy,

        recommendations: &[TuningRecommendation],

        parameters: &Arc<RwLock<HashMap<String, TuningParameter>>>,

        applied_changes: &Arc<RwLock<Vec<AppliedChange>>>,

        system_state: &Arc<RwLock<SystemState>>,

        config: &AutoTuningConfig,

    ) -> Result<()> {

        let params_guard = parameters.read().await;

        let state = system_state.read().await;



        // Find relevant recommendations for this strategy

        let relevant_recommendations: Vec<&TuningRecommendation> = recommendations

            .iter()

            .filter(|rec| {

                // Check if recommendation targets parameters in this strategy

                strategy.target_parameters.iter().any(|param| {

                    rec.recommendation_type == Self::recommendation_type_from_parameter(param)

                })

            })

            .collect();



        for recommendation in relevant_recommendations {

            // Find the parameter to tune

            let parameter_name = Self::parameter_from_recommendation(&recommendation.recommendation_type);

            

            if let Some(parameter) = params_guard.get(&parameter_name) {

                // Calculate new value

                if let Some(new_value) = Self::calculate_optimal_value(parameter, &state, config)? {

                    // Check if change is significant enough

                    let change_percentage = Self::calculate_change_percentage(&parameter.current_value, &new_value);

                    

                    if change_percentage >= 5.0 && change_percentage <= (config.max_change_percentage * 100.0) {

                        // Apply the change

                        let applied_change = AppliedChange {

                            id: Uuid::new_v4().to_string(),

                            parameter_name: parameter_name.clone(),

                            previous_value: parameter.current_value.clone(),

                            new_value: new_value.clone(),

                            reason: recommendation.description.clone(),

                            expected_improvement: recommendation.expected_improvement.clone(),

                            confidence: 0.8, // Would calculate based on data

                            applied_at: chrono::Utc::now(),

                            impact_level: parameter.impact_level,

                            metrics_before: state.performance_metrics.clone(),

                            metrics_after: None,

                            status: ChangeStatus::Applied,

                            rollback_info: None,

                        };



                        // Actually apply the parameter change

                        Self::apply_parameter_change(&applied_change).await?;



                        // Record the change

                        let mut changes = applied_changes.write().await;

                        changes.push(applied_change);

                    }

                }

            }

        }



        Ok(())

    }



    /// Map recommendation type to parameter name

    fn parameter_from_recommendation(recommendation_type: &RecommendationType) -> String {

        match recommendation_type {

            RecommendationType::IncreaseCacheSize => "cache_size".to_string(),

            RecommendationType::AdjustConnectionPool => "max_connections".to_string(),

            RecommendationType::AdjustTimeouts => "connection_timeout_seconds".to_string(),

            _ => String::new(),

        }

    }



    /// Map parameter name to recommendation type

    fn recommendation_type_from_parameter(parameter_name: &str) -> RecommendationType {

        match parameter_name {

            "cache_size" => RecommendationType::IncreaseCacheSize,

            "max_connections" => RecommendationType::AdjustConnectionPool,

            "connection_timeout_seconds" => RecommendationType::AdjustTimeouts,

            _ => RecommendationType::IncreaseCacheSize, // Default

        }

    }



    /// Calculate optimal value for a parameter

    fn calculate_optimal_value(

        parameter: &TuningParameter,

        _system_state: &SystemState,

        config: &AutoTuningConfig,

    ) -> Result<Option<serde_json::Value>> {

        let current_value = &parameter.current_value;

        

        match parameter.data_type {

            ParameterType::Integer => {

                let current = current_value.as_i64().unwrap_or(0) as i64;

                let step = parameter.step_size.as_ref()

                    .and_then(|s| s.as_i64())

                    .unwrap_or(1);

                

                let new_value = if config.enable_gradual_changes {

                    // Gradual change

                    current + (step / 2)

                } else {

                    // Full step

                    current + step

                };



                // Check bounds

                let min_bound = parameter.min_value.as_ref().and_then(|v| v.as_i64()).unwrap_or(i64::MIN);

                let max_bound = parameter.max_value.as_ref().and_then(|v| v.as_i64()).unwrap_or(i64::MAX);

                

                if new_value >= min_bound && new_value <= max_bound {

                    Ok(Some(serde_json::Value::Number(serde_json::Number::from(new_value))))

                } else {

                    Ok(None)

                }

            }

            ParameterType::Float => {

                let current = current_value.as_f64().unwrap_or(0.0);

                let step = parameter.step_size.as_ref()

                    .and_then(|s| s.as_f64())

                    .unwrap_or(0.1);

                

                let new_value = if config.enable_gradual_changes {

                    current + (step / 2.0)

                } else {

                    current + step

                };



                let min_bound = parameter.min_value.as_ref().and_then(|v| v.as_f64()).unwrap_or(f64::NEG_INFINITY);

                let max_bound = parameter.max_value.as_ref().and_then(|v| v.as_f64()).unwrap_or(f64::INFINITY);

                

                if new_value >= min_bound && new_value <= max_bound {

                    Ok(Some(serde_json::Value::Number(serde_json::Number::from_f64(new_value).unwrap()))

                    )

                } else {

                    Ok(None)

                }

            }

            _ => Ok(None), // Other types not supported for auto-tuning yet

        }

    }



    /// Calculate percentage change between two values

    fn calculate_change_percentage(old_value: &serde_json::Value, new_value: &serde_json::Value) -> f64 {

        match (old_value.as_f64(), new_value.as_f64()) {

            (Some(old), Some(new)) => {

                if old == 0.0 {

                    if new == 0.0 { 0.0 } else { 100.0 }

                } else {

                    ((new - old).abs() / old.abs()) * 100.0

                }

            }

            _ => 0.0,

        }

    }



    /// Apply a parameter change to the system

    async fn apply_parameter_change(change: &AppliedChange) -> Result<()> {

        // In a real implementation, this would update the actual configuration

        println!("Applying parameter change: {} = {:?} (was {:?})",

            change.parameter_name,

            change.new_value,

            change.previous_value

        );



        // This would interface with the actual configuration system

        // For now, we just log the change



        Ok(())

    }



    /// Clean up old applied changes

    async fn cleanup_old_changes(

        applied_changes: &Arc<RwLock<Vec<AppliedChange>>>,

        _config: &AutoTuningConfig,

    ) -> Result<()> {

        let cutoff = chrono::Utc::now() - chrono::Duration::days(7); // Keep changes for 7 days

        let mut changes = applied_changes.write().await;

        let initial_len = changes.len();

        

        changes.retain(|change| {

            change.applied_at > cutoff || 

            change.status == ChangeStatus::Observing ||

            change.status == ChangeStatus::Applied

        });



        let cleaned_up = initial_len - changes.len();

        if cleaned_up > 0 {

            println!("Cleaned up {} old tuning changes", cleaned_up);

        }



        Ok(())

    }



    /// Get current tuning status

    pub async fn get_tuning_status(&self) -> Result<TuningStatus> {

        let system_state = self.system_state.read().await;

        let applied_changes = self.applied_changes.read().await;

        let strategies = self.strategies.read().await;



        let recent_changes: Vec<&AppliedChange> = applied_changes

            .iter()

            .filter(|change| {

                change.applied_at > chrono::Utc::now() - chrono::Duration::hours(24)

            })

            .collect();



        let active_strategies: Vec<&TuningStrategy> = strategies

            .iter()

            .filter(|s| s.enabled)

            .collect();



        Ok(TuningStatus {

            enabled: self.config.enabled,

            system_state: system_state.clone(),

            recent_changes_count: recent_changes.len(),

            active_strategies_count: active_strategies.len(),

            last_tuning_cycle: system_state.last_updated,

            auto_rollback_enabled: self.config.enable_auto_rollback,

            safety_mode: self.config.safety_mode,

        })

    }



    /// Manually apply a tuning recommendation

    pub async fn apply_recommendation(&self, recommendation: &TuningRecommendation) -> Result<String> {

        let parameter_name = Self::parameter_from_recommendation(&recommendation.recommendation_type);

        let params = self.parameters.read().await;

        

        if let Some(parameter) = params.get(&parameter_name) {

            let change_id = Uuid::new_v4().to_string();

            let system_state = self.system_state.read().await;



            let applied_change = AppliedChange {

                id: change_id.clone(),

                parameter_name: parameter_name.clone(),

                previous_value: parameter.current_value.clone(),

                new_value: serde_json::Value::Number(serde_json::Number::from(2000)), // Example new value

                reason: recommendation.description.clone(),

                expected_improvement: recommendation.expected_improvement.clone(),

                confidence: 0.9,

                applied_at: chrono::Utc::now(),

                impact_level: parameter.impact_level,

                metrics_before: system_state.performance_metrics.clone(),

                metrics_after: None,

                status: ChangeStatus::Applied,

                rollback_info: None,

            };



            Self::apply_parameter_change(&applied_change).await?;



            let mut changes = self.applied_changes.write().await;

            changes.push(applied_change);



            Ok(change_id)

        } else {

            Err(FortressError::storage(

                format!("Parameter not found: {}", parameter_name),

                "auto_tuning".to_string(),

                crate::error::StorageErrorCode::NotFound,

            ))

        }

    }

}



/// Tuning status information

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct TuningStatus {

    /// Auto-tuning enabled

    pub enabled: bool,

    /// Current system state

    pub system_state: SystemState,

    /// Number of recent changes

    pub recent_changes_count: usize,

    /// Number of active strategies

    pub active_strategies_count: usize,

    /// Last tuning cycle timestamp

    pub last_tuning_cycle: chrono::DateTime<chrono::Utc>,

    /// Auto-rollback enabled

    pub auto_rollback_enabled: bool,

    /// Safety mode enabled

    pub safety_mode: bool,

}


/// System state

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct SystemState {

    /// Performance metrics

    pub performance_metrics: HashMap<String, f64>,

    /// System load

    pub system_load: f64,

    /// Active connections

    pub active_connections: u32,

    /// Memory usage percent

    pub memory_usage_percent: f64,

    /// CPU usage percent

    pub cpu_usage_percent: f64,

    /// Cache hit ratio

    pub cache_hit_ratio: f64,

    /// Error rate

    pub error_rate: f64,

    /// Last updated timestamp

    pub last_updated: chrono::DateTime<chrono::Utc>,

}

/// Applied change

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct AppliedChange {

    /// Change ID

    pub id: String,

    /// Parameter name

    pub parameter_name: String,

    /// Previous value

    pub previous_value: serde_json::Value,

    /// New value

    pub new_value: serde_json::Value,

    /// Reason

    pub reason: String,

    /// Expected improvement

    pub expected_improvement: String,

    /// Confidence

    pub confidence: f64,

    /// Applied at timestamp

    pub applied_at: chrono::DateTime<chrono::Utc>,

    /// Impact level

    pub impact_level: ImpactLevel,

    /// Metrics before

    pub metrics_before: HashMap<String, f64>,

    /// Metrics after

    pub metrics_after: Option<HashMap<String, f64>>,

    /// Status

    pub status: ChangeStatus,

    /// Rollback info

    pub rollback_info: Option<RollbackInfo>,

}

/// Change status



/// Recommendation type

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]

pub enum RecommendationType {

    /// Increase cache size

    IncreaseCacheSize,

    /// Decrease cache size

    DecreaseCacheSize,

    /// Increase max connections

    IncreaseMaxConnections,

    /// Decrease max connections

    DecreaseMaxConnections,

    /// Adjust connection pool

    AdjustConnectionPool,

    /// Adjust timeouts

    AdjustTimeouts,

}

/// Implementation complexity

#[derive(Debug, Clone, Serialize, Deserialize)]

pub enum ImplementationComplexity {

    /// Low

    Low,

    /// Medium

    Medium,

    /// High

    High,

}

/// Recommendation priority

#[derive(Debug, Clone, Serialize, Deserialize)]

pub enum RecommendationPriority {

    /// Low

    Low,

    /// Medium

    Medium,

    /// High

    High,

    /// Critical

    Critical,

}

/// Tuning recommendation

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct TuningRecommendation {

    /// ID

    pub id: String,

    /// Recommendation type

    pub recommendation_type: RecommendationType,

    /// Description

    pub description: String,

    /// Expected improvement

    pub expected_improvement: String,

    /// Complexity

    pub complexity: ImplementationComplexity,

    /// Priority

    pub priority: RecommendationPriority,

    /// Parameters

    pub parameters: HashMap<String, serde_json::Value>,

}

#[cfg(test)]

mod tests {

    use super::*;

    use crate::performance_monitor::PerformanceMonitorConfig;

    use crate::prelude::{ImplementationComplexity, RecommendationPriority};

    #[tokio::test]

    async fn test_auto_tuner_initialization() {

        let config = AutoTuningConfig::default();

        let perf_config = PerformanceMonitorConfig::default();

        let performance_monitor = Arc::new(PerformanceMonitor::new(perf_config));

        

        let tuner = AutomaticPerformanceTuner::new(config, performance_monitor).await;



        // Check that parameters were initialized

        let parameters = tuner.parameters.read().await;

        assert!(parameters.contains_key("cache_size"));

        assert!(parameters.contains_key("max_connections"));



        // Check that strategies were initialized

        let strategies = tuner.strategies.read().await;

        assert!(!strategies.is_empty());

    }



    #[tokio::test]

    async fn test_tuning_status() {

        let config = AutoTuningConfig::default();

        let perf_config = PerformanceMonitorConfig::default();

        let performance_monitor = Arc::new(PerformanceMonitor::new(perf_config));

        

        let tuner = AutomaticPerformanceTuner::new(config, performance_monitor).await;



        let status = tuner.get_tuning_status().await.unwrap();

        assert!(status.enabled);

        assert!(status.auto_rollback_enabled);

        assert!(status.safety_mode);

    }



    #[tokio::test]

    async fn test_manual_recommendation_application() {

        let config = AutoTuningConfig::default();

        let perf_config = PerformanceMonitorConfig::default();

        let performance_monitor = Arc::new(PerformanceMonitor::new(perf_config));

        

        let tuner = AutomaticPerformanceTuner::new(config, performance_monitor).await;



        let recommendation = TuningRecommendation {

            id: "test_rec".to_string(),

            recommendation_type: RecommendationType::IncreaseCacheSize,

            description: "Test recommendation".to_string(),

            expected_improvement: "10% improvement".to_string(),

            complexity: PmImplementationComplexity::Low,

            priority: PmRecommendationPriority::Medium,

            parameters: HashMap::new(),

        };



        let change_id = tuner.apply_recommendation(&recommendation).await.unwrap();

        assert!(!change_id.is_empty());



        // Check that the change was recorded

        let changes = tuner.applied_changes.read().await;

        assert!(changes.iter().any(|c| c.id == change_id));

    }



    #[tokio::test]

    async fn test_parameter_value_calculation() {

        let config = AutoTuningConfig::default();

        let perf_config = PerformanceMonitorConfig::default();

        let performance_monitor = Arc::new(PerformanceMonitor::new(perf_config));

        

        let tuner = AutomaticPerformanceTuner::new(config, performance_monitor).await;



        let parameter = TuningParameter {

            name: "test_param".to_string(),

            current_value: serde_json::Value::Number(serde_json::Number::from(100)),

            data_type: ParameterType::Integer,

            min_value: Some(serde_json::Value::Number(serde_json::Number::from(50))),

            max_value: Some(serde_json::Value::Number(serde_json::Number::from(200))),

            step_size: Some(serde_json::Value::Number(serde_json::Number::from(10))),

            category: ParameterCategory::Cache,

            impact_level: ImpactLevel::Low,

            requires_restart: false,

            description: "Test parameter".to_string(),

        };



        let system_state = SystemState {

            performance_metrics: HashMap::new(),

            system_load: 0.0,

            active_connections: 0,

            memory_usage_percent: 0.0,

            cpu_usage_percent: 0.0,

            cache_hit_ratio: 0.0,

            error_rate: 0.0,

            last_updated: chrono::Utc::now(),

        };



        let new_value = AutomaticPerformanceTuner::calculate_optimal_value(

            &parameter,

            &system_state,

            &tuner.config,

        ).unwrap();



        assert!(new_value.is_some());

        let new_int = new_value.unwrap().as_i64().unwrap();

        assert!(new_int > 100); // Should increase

        assert!(new_int <= 200); // Should not exceed max

    }

}

