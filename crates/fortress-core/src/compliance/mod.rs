//! Compliance Framework for Fortress
//!
//! This module provides comprehensive compliance support for major regulatory frameworks
//! including GDPR, HIPAA, and PCI-DSS. It implements data protection, audit trails,
//! consent management, and reporting capabilities required for enterprise deployments.

pub mod framework;
pub mod gdpr;
pub mod hipaa;
pub mod pci_dss;
pub mod reporting;
pub mod audit;
pub mod config;
pub mod unified_manager;

pub use framework::*;
pub use gdpr::*;
pub use hipaa::*;
pub use pci_dss::*;
pub use reporting::*;
pub use audit::*;
pub use config::*;
pub use unified_manager::*;

// Re-export RiskLevel to avoid ambiguity
pub use pci_dss::RiskLevel;
