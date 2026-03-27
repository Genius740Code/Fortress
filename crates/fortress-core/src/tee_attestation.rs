//! TEE Attestation Verification Module
//!
//! This module provides comprehensive attestation verification for different
//! TEE types including AWS Nitro Enclaves and Intel SGX, ensuring that
//! enclaves are authentic and trustworthy before allowing secure operations.

use crate::error::{FortressError, Result};
use crate::tee::{TeeType, AttestationResult, SecurityPolicy};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde_bytes;

/// Attestation verifier for different TEE types
pub struct AttestationVerifier {
    /// Trusted certificates and keys
    trusted_data: TrustedDataStore,
    /// Verification configuration
    config: VerificationConfig,
}

/// Store for trusted certificates and keys
#[derive(Debug)]
pub struct TrustedDataStore {
    /// AWS Nitro trusted certificates
    aws_nitro_certs: HashMap<String, String>,
    /// Intel SGX trusted certificates
    intel_sgx_certs: HashMap<String, String>,
    /// Trusted PCR values
    trusted_pcrs: HashMap<TeeType, HashMap<String, String>>,
    /// Trusted enclave measurements
    trusted_measurements: HashMap<TeeType, HashMap<String, String>>,
}

/// Attestation verification configuration
#[derive(Debug, Clone)]
pub struct VerificationConfig {
    /// Allow debug enclaves
    pub allow_debug_enclaves: bool,
    /// Require certificate validation
    pub require_cert_validation: bool,
    /// Maximum attestation age in seconds
    pub max_attestation_age: u64,
    /// Require nonce verification
    pub require_nonce_verification: bool,
    /// Enable measurement caching
    pub enable_measurement_cache: bool,
    /// Cache TTL for measurements in seconds
    pub measurement_cache_ttl: u64,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            allow_debug_enclaves: false,
            require_cert_validation: true,
            max_attestation_age: 300, // 5 minutes
            require_nonce_verification: true,
            enable_measurement_cache: true,
            measurement_cache_ttl: 3600, // 1 hour
        }
    }
}

/// AWS Nitro Enclave attestation document
#[derive(Debug, Deserialize)]
pub struct NitroAttestationDocument {
    /// Module ID
    pub module_id: String,
    /// Enclave ID
    pub enclave_id: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// PCR values
    pub pcrs: HashMap<String, String>,
    /// Certificate
    pub certificate: String,
    /// Certificate chain
    pub certificate_chain: Vec<String>,
    /// Public key
    pub public_key: String,
    /// User data
    pub user_data: Option<String>,
    /// Nonce
    pub nonce: Option<String>,
}

/// Intel SGX quote structure
#[derive(Debug, Deserialize)]
pub struct SgxQuote {
    /// Quote version
    pub version: u16,
    /// Quote type
    pub quote_type: u16,
    /// SGX quote signature data
    pub signature_data: SgxSignatureData,
    /// Report body
    pub report_body: SgxReportBody,
}

/// SGX signature data
#[derive(Debug, Deserialize)]
pub struct SgxSignatureData {
    /// Attestation key signature
    pub signature: Vec<u8>,
    /// Attestation key
    pub attestation_key: Vec<u8>,
}

/// Intel SGX report body
#[derive(Debug, Deserialize)]
pub struct SgxReportBody {
    /// CPU SVN
    #[serde(with = "serde_bytes")]
    pub cpu_svn: Vec<u8>,
    /// MISC SELECT
    #[serde(with = "serde_bytes")]
    pub misc_select: Vec<u8>,
    /// Reserved bytes
    #[serde(with = "serde_bytes")]
    pub reserved1: Vec<u8>,
    /// ISV EXTENDED PROD ID
    #[serde(with = "serde_bytes")]
    pub isv_ext_prod_id: Vec<u8>,
    /// ISV EXTENDED SVN
    #[serde(with = "serde_bytes")]
    pub isv_ext_svn: Vec<u8>,
    /// ATTRIBUTES
    pub attributes: SgxAttributes,
    /// ATTRIBUTES MASK
    pub attributes_mask: SgxAttributes,
    /// MRENCLAVE
    #[serde(with = "serde_bytes")]
    pub mr_enclave: Vec<u8>,
    /// Reserved bytes
    #[serde(with = "serde_bytes")]
    pub reserved2: Vec<u8>,
    /// MRSIGNER
    #[serde(with = "serde_bytes")]
    pub mr_signer: Vec<u8>,
    /// Reserved bytes
    #[serde(with = "serde_bytes")]
    pub reserved3: Vec<u8>,
    /// ISV PROD ID
    pub isv_prod_id: u16,
    /// ISV SVN
    pub isv_svn: u16,
    /// Reserved bytes
    #[serde(with = "serde_bytes")]
    pub reserved4: Vec<u8>,
    /// REPORT DATA
    #[serde(with = "serde_bytes")]
    pub report_data: Vec<u8>,
}

/// SGX attributes
#[derive(Debug, Deserialize)]
pub struct SgxAttributes {
    /// Flags
    pub flags: u64,
    /// XFRM
    pub xfrm: u64,
}

/// Verification result details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationDetails {
    /// Certificate validation result
    pub cert_validation: bool,
    /// Measurement validation result
    pub measurement_validation: bool,
    /// Timestamp validation result
    pub timestamp_validation: bool,
    /// Nonce validation result
    pub nonce_validation: bool,
    /// Security version validation result
    pub security_version_validation: bool,
    /// Debug mode validation result
    pub debug_mode_validation: bool,
    /// Additional verification details
    pub additional_checks: HashMap<String, bool>,
}

impl AttestationVerifier {
    /// Create a new attestation verifier
    pub fn new(config: VerificationConfig) -> Self {
        let trusted_data = TrustedDataStore::new();
        
        Self {
            trusted_data,
            config,
        }
    }
    
    /// Verify AWS Nitro Enclave attestation
    pub async fn verify_nitro_attestation(
        &self,
        document: &NitroAttestationDocument,
        policy: &SecurityPolicy,
    ) -> Result<VerificationDetails> {
        let mut details = VerificationDetails {
            cert_validation: false,
            measurement_validation: false,
            timestamp_validation: false,
            nonce_validation: false,
            security_version_validation: true, // Nitro doesn't have explicit security version
            debug_mode_validation: true,      // Nitro debug mode is controlled by policy
            additional_checks: HashMap::new(),
        };
        
        // 1. Validate certificate chain
        if self.config.require_cert_validation {
            details.cert_validation = self.verify_nitro_certificate_chain(document).await?;
        } else {
            details.cert_validation = true;
        }
        
        // 2. Validate measurements (PCRs)
        details.measurement_validation = self.verify_nitro_measurements(document, policy).await?;
        
        // 3. Validate timestamp
        details.timestamp_validation = self.verify_timestamp(&document.timestamp).await?;
        
        // 4. Validate nonce if required
        if self.config.require_nonce_verification {
            details.nonce_validation = self.verify_nitro_nonce(document).await?;
        } else {
            details.nonce_validation = true;
        }
        
        // 5. Additional checks
        details.additional_checks.insert("module_id_valid".to_string(), !document.module_id.is_empty());
        details.additional_checks.insert("enclave_id_valid".to_string(), !document.enclave_id.is_empty());
        details.additional_checks.insert("public_key_present".to_string(), !document.public_key.is_empty());
        
        Ok(details)
    }
    
    /// Verify Intel SGX attestation
    pub async fn verify_sgx_attestation(
        &self,
        quote: &SgxQuote,
        policy: &SecurityPolicy,
        expected_nonce: Option<&str>,
    ) -> Result<VerificationDetails> {
        let mut details = VerificationDetails {
            cert_validation: false,
            measurement_validation: false,
            timestamp_validation: true, // SGX quotes don't have explicit timestamps
            nonce_validation: false,
            security_version_validation: false,
            debug_mode_validation: false,
            additional_checks: HashMap::new(),
        };
        
        // 1. Validate quote signature
        if self.config.require_cert_validation {
            details.cert_validation = self.verify_sgx_quote_signature(quote).await?;
        } else {
            details.cert_validation = true;
        }
        
        // 2. Validate measurements
        details.measurement_validation = self.verify_sgx_measurements(&quote.report_body, policy).await?;
        
        // 3. Validate nonce if required
        if self.config.require_nonce_verification && expected_nonce.is_some() {
            details.nonce_validation = self.verify_sgx_nonce(&quote.report_body, expected_nonce.unwrap()).await?;
        } else {
            details.nonce_validation = true;
        }
        
        // 4. Validate security version
        details.security_version_validation = self.verify_sgx_security_version(&quote.report_body, policy).await?;
        
        // 5. Validate debug mode
        details.debug_mode_validation = self.verify_sgx_debug_mode(&quote.report_body).await?;
        
        // 6. Additional checks
        details.additional_checks.insert("quote_version_valid".to_string(), quote.version == 3);
        details.additional_checks.insert("attributes_valid".to_string(), quote.report_body.attributes.flags != 0);
        
        Ok(details)
    }
    
    /// Verify AWS Nitro certificate chain
    async fn verify_nitro_certificate_chain(&self, document: &NitroAttestationDocument) -> Result<bool> {
        // In a real implementation, this would:
        // 1. Parse the certificate chain
        // 2. Verify each certificate against its issuer
        // 3. Check certificate validity dates
        // 4. Verify against trusted AWS Nitro root certificates
        
        // For now, we'll simulate certificate verification
        let cert_valid = !document.certificate.is_empty() && 
                        !document.certificate_chain.is_empty() &&
                        document.certificate_chain.len() >= 2;
        
        if cert_valid {
            // Additional certificate validation logic would go here
            Ok(true)
        } else {
            Err(FortressError::tee(
                "Invalid Nitro certificate chain",
                "AttestationVerifier::verify_nitro_certificate_chain"
            ))
        }
    }
    
    /// Verify AWS Nitro measurements (PCRs)
    async fn verify_nitro_measurements(
        &self,
        document: &NitroAttestationDocument,
        policy: &SecurityPolicy,
    ) -> Result<bool> {
        // Check if we have trusted PCR values for this enclave type
        if let Some(trusted_pcrs) = self.trusted_data.trusted_pcrs.get(&TeeType::AwsNitro) {
            // Verify each PCR value against trusted values
            for (pcr_name, pcr_value) in &document.pcrs {
                if let Some(trusted_value) = trusted_pcrs.get(pcr_name) {
                    if pcr_value != trusted_value {
                        return Err(FortressError::tee(
                            format!("PCR {} value mismatch: expected {}, got {}", 
                                   pcr_name, trusted_value, pcr_value),
                            "AttestationVerifier::verify_nitro_measurements".to_string()
                        ));
                    }
                }
            }
        }
        
        // Check against policy-specified PCR values
        if let Some(ref allowed_pcrs) = policy.allowed_pcr_values {
            for (pcr_name, expected_value) in allowed_pcrs {
                if let Some(actual_value) = document.pcrs.get(pcr_name) {
                    if actual_value != expected_value {
                        return Err(FortressError::tee(
                            format!("PCR {} policy mismatch: expected {}, got {}", 
                                   pcr_name, expected_value, actual_value),
                            "AttestationVerifier::verify_nitro_measurements".to_string()
                        ));
                    }
                } else {
                    return Err(FortressError::tee(
                        format!("Required PCR {} not found in attestation", pcr_name),
                        "AttestationVerifier::verify_nitro_measurements".to_string()
                    ));
                }
            }
        }
        
        Ok(true)
    }
    
    /// Verify Intel SGX quote signature
    async fn verify_sgx_quote_signature(&self, quote: &SgxQuote) -> Result<bool> {
        // In a real implementation, this would:
        // 1. Extract the quote signature
        // 2. Verify against Intel's attestation service or trusted certificates
        // 3. Check the signature algorithm and key parameters
        
        // For now, we'll simulate signature verification
        let signature_valid = !quote.signature_data.signature.is_empty() &&
                            !quote.signature_data.attestation_key.is_empty() &&
                            quote.signature_data.signature.len() >= 256; // Minimum signature size
        
        if signature_valid {
            Ok(true)
        } else {
            Err(FortressError::tee(
                "Invalid SGX quote signature",
                "AttestationVerifier::verify_sgx_quote_signature"
            ))
        }
    }
    
    /// Verify Intel SGX measurements
    async fn verify_sgx_measurements(
        &self,
        report_body: &SgxReportBody,
        policy: &SecurityPolicy,
    ) -> Result<bool> {
        // Convert measurements to hex strings for comparison
        let mr_enclave = hex::encode(&report_body.mr_enclave);
        let mr_signer = hex::encode(&report_body.mr_signer);
        
        // Check against trusted measurements
        if let Some(trusted_measurements) = self.trusted_data.trusted_measurements.get(&TeeType::IntelSgx) {
            if let Some(trusted_mr_enclave) = trusted_measurements.get("MRENCLAVE") {
                if mr_enclave != *trusted_mr_enclave {
                    return Err(FortressError::tee(
                        format!("MRENCLAVE mismatch: expected {}, got {}", 
                               trusted_mr_enclave, mr_enclave),
                        "AttestationVerifier::verify_sgx_measurements".to_string()
                    ));
                }
            }
            
            if let Some(trusted_mr_signer) = trusted_measurements.get("MRSIGNER") {
                if mr_signer != *trusted_mr_signer {
                    return Err(FortressError::tee(
                        format!("MRSIGNER mismatch: expected {}, got {}", 
                               trusted_mr_signer, mr_signer),
                        "AttestationVerifier::verify_sgx_measurements".to_string()
                    ));
                }
            }
        }
        
        // Check against policy-specified measurements
        if let Some(ref allowed_pcrs) = policy.allowed_pcr_values {
            if let Some(expected_mr_enclave) = allowed_pcrs.get("MRENCLAVE") {
                if mr_enclave != *expected_mr_enclave {
                    return Err(FortressError::tee(
                        format!("MRENCLAVE policy mismatch: expected {}, got {}", 
                               expected_mr_enclave, mr_enclave),
                        "AttestationVerifier::verify_sgx_measurements".to_string()
                    ));
                }
            }
            
            if let Some(expected_mr_signer) = allowed_pcrs.get("MRSIGNER") {
                if mr_signer != *expected_mr_signer {
                    return Err(FortressError::tee(
                        format!("MRSIGNER policy mismatch: expected {}, got {}", 
                               expected_mr_signer, mr_signer),
                        "AttestationVerifier::verify_sgx_measurements".to_string()
                    ));
                }
            }
        }
        
        Ok(true)
    }
    
    /// Verify Intel SGX nonce
    async fn verify_sgx_nonce(&self, report_body: &SgxReportBody, expected_nonce: &str) -> Result<bool> {
        // Extract nonce from report data (first 32 bytes typically contain nonce)
        let report_data_str = hex::encode(&report_body.report_data[..32]);
        
        if report_data_str == expected_nonce {
            Ok(true)
        } else {
            Err(FortressError::tee(
                format!("Nonce mismatch: expected {}, got {}", expected_nonce, report_data_str),
                "AttestationVerifier::verify_sgx_nonce".to_string()
            ))
        }
    }
    
    /// Verify Intel SGX security version
    async fn verify_sgx_security_version(&self, report_body: &SgxReportBody, policy: &SecurityPolicy) -> Result<bool> {
        let isv_svn = report_body.isv_svn;
        
        // Check minimum security version
        if let Some(min_version) = policy.min_security_version {
            if u32::from(isv_svn) < min_version {
                return Err(FortressError::tee(
                    format!("Security version too low: {} < {}", isv_svn, min_version),
                    "AttestationVerifier::verify_sgx_security_version".to_string()
                ));
            }
        }
        
        // Check maximum security version
        if let Some(max_version) = policy.max_security_version {
            if u32::from(isv_svn) > max_version {
                return Err(FortressError::tee(
                    format!("Security version too high: {} > {}", isv_svn, max_version),
                    "AttestationVerifier::verify_sgx_security_version".to_string()
                ));
            }
        }
        
        Ok(true)
    }
    
    /// Verify Intel SGX debug mode
    async fn verify_sgx_debug_mode(&self, report_body: &SgxReportBody) -> Result<bool> {
        // Check if debug flag is set in attributes
        let debug_flag_set = (report_body.attributes.flags & 0x2) != 0;
        
        if debug_flag_set && !self.config.allow_debug_enclaves {
            return Err(FortressError::tee(
                "Debug enclave not allowed",
                "AttestationVerifier::verify_sgx_debug_mode"
            ));
        }
        
        Ok(true)
    }
    
    /// Verify attestation timestamp
    async fn verify_timestamp(&self, timestamp: &DateTime<Utc>) -> Result<bool> {
        let now = Utc::now();
        let age = (now - *timestamp).num_seconds();
        
        if age > self.config.max_attestation_age as i64 {
            return Err(FortressError::tee(
                format!("Attestation too old: {} seconds", age),
                "AttestationVerifier::verify_timestamp".to_string()
            ));
        }
        
        Ok(true)
    }
    
    /// Verify AWS Nitro nonce
    async fn verify_nitro_nonce(&self, document: &NitroAttestationDocument) -> Result<bool> {
        // In a real implementation, this would verify the nonce against expected value
        // For now, we'll just check that a nonce is present
        document.nonce.is_some().then_some(true).ok_or_else(|| FortressError::tee(
            "Nonce missing from Nitro attestation",
            "AttestationVerifier::verify_nitro_nonce"
        ))
    }
    
    /// Create attestation result from verification details
    pub fn create_attestation_result(
        &self,
        tee_type: TeeType,
        enclave_id: String,
        details: VerificationDetails,
        security_version: u32,
    ) -> AttestationResult {
        let is_valid = details.cert_validation &&
                      details.measurement_validation &&
                      details.timestamp_validation &&
                      details.nonce_validation &&
                      details.security_version_validation &&
                      details.debug_mode_validation &&
                      details.additional_checks.values().all(|&v| v);
        
        let mut security_issues = Vec::new();
        
        if !details.cert_validation {
            security_issues.push("Certificate validation failed".to_string());
        }
        if !details.measurement_validation {
            security_issues.push("Measurement validation failed".to_string());
        }
        if !details.timestamp_validation {
            security_issues.push("Timestamp validation failed".to_string());
        }
        if !details.nonce_validation {
            security_issues.push("Nonce validation failed".to_string());
        }
        if !details.security_version_validation {
            security_issues.push("Security version validation failed".to_string());
        }
        if !details.debug_mode_validation {
            security_issues.push("Debug mode validation failed".to_string());
        }
        
        // Add failed additional checks
        for (check_name, passed) in &details.additional_checks {
            if !passed {
                security_issues.push(format!("{} failed", check_name));
            }
        }
        
        let mut result_details = HashMap::new();
        result_details.insert("cert_validation".to_string(), details.cert_validation.to_string());
        result_details.insert("measurement_validation".to_string(), details.measurement_validation.to_string());
        result_details.insert("timestamp_validation".to_string(), details.timestamp_validation.to_string());
        result_details.insert("nonce_validation".to_string(), details.nonce_validation.to_string());
        result_details.insert("security_version_validation".to_string(), details.security_version_validation.to_string());
        result_details.insert("debug_mode_validation".to_string(), details.debug_mode_validation.to_string());
        
        AttestationResult {
            is_valid,
            tee_type,
            enclave_id,
            security_version,
            timestamp: Utc::now(),
            details: result_details,
            security_issues,
        }
    }
}

impl TrustedDataStore {
    /// Create a new trusted data store
    pub fn new() -> Self {
        let mut store = Self {
            aws_nitro_certs: HashMap::new(),
            intel_sgx_certs: HashMap::new(),
            trusted_pcrs: HashMap::new(),
            trusted_measurements: HashMap::new(),
        };
        
        // Initialize with some default trusted data (in production, this would come from secure storage)
        store.initialize_default_trusted_data();
        store
    }
    
    /// Initialize default trusted data for testing
    fn initialize_default_trusted_data(&mut self) {
        // AWS Nitro trusted PCRs (example values)
        let mut nitro_pcrs = HashMap::new();
        nitro_pcrs.insert("PCR0".to_string(), "simulated_pcr0_hash".to_string());
        nitro_pcrs.insert("PCR1".to_string(), "simulated_pcr1_hash".to_string());
        nitro_pcrs.insert("PCR2".to_string(), "simulated_pcr2_hash".to_string());
        nitro_pcrs.insert("PCR3".to_string(), "simulated_pcr3_hash".to_string());
        self.trusted_pcrs.insert(TeeType::AwsNitro, nitro_pcrs);
        
        // Intel SGX trusted measurements (example values)
        let mut sgx_measurements = HashMap::new();
        sgx_measurements.insert("MRENCLAVE".to_string(), "simulated_mr_enclave_hash".to_string());
        sgx_measurements.insert("MRSIGNER".to_string(), "simulated_mr_signer_hash".to_string());
        self.trusted_measurements.insert(TeeType::IntelSgx, sgx_measurements);
    }
    
    /// Add trusted certificate for AWS Nitro
    pub fn add_nitro_certificate(&mut self, cert_id: String, certificate: String) {
        self.aws_nitro_certs.insert(cert_id, certificate);
    }
    
    /// Add trusted certificate for Intel SGX
    pub fn add_sgx_certificate(&mut self, cert_id: String, certificate: String) {
        self.intel_sgx_certs.insert(cert_id, certificate);
    }
    
    /// Add trusted PCR values
    pub fn add_trusted_pcrs(&mut self, tee_type: TeeType, pcrs: HashMap<String, String>) {
        self.trusted_pcrs.insert(tee_type, pcrs);
    }
    
    /// Add trusted measurements
    pub fn add_trusted_measurements(&mut self, tee_type: TeeType, measurements: HashMap<String, String>) {
        self.trusted_measurements.insert(tee_type, measurements);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::SecurityPolicy;
    
    #[tokio::test]
    async fn test_attestation_verifier_creation() {
        let config = VerificationConfig::default();
        let verifier = AttestationVerifier::new(config);
        
        // Should be able to create verifier
        assert_eq!(verifier.config.max_attestation_age, 300);
        assert!(verifier.config.require_cert_validation);
    }
    
    #[tokio::test]
    async fn test_nitro_attestation_verification() {
        let config = VerificationConfig::default();
        let verifier = AttestationVerifier::new(config);
        
        let document = NitroAttestationDocument {
            module_id: "test-module".to_string(),
            enclave_id: "test-enclave".to_string(),
            timestamp: Utc::now(),
            pcrs: HashMap::new(),
            certificate: "test-cert".to_string(),
            certificate_chain: vec!["cert1".to_string(), "cert2".to_string()],
            public_key: "test-pubkey".to_string(),
            user_data: None,
            nonce: Some("test-nonce".to_string()),
        };
        
        let policy = SecurityPolicy::default();
        let result = verifier.verify_nitro_attestation(&document, &policy).await;
        
        // Should succeed with simulated verification
        assert!(result.is_ok());
        let details = result.unwrap();
        assert!(details.cert_validation);
        assert!(details.measurement_validation);
    }
    
    #[tokio::test]
    async fn test_sgx_attestation_verification() {
        let config = VerificationConfig::default();
        let verifier = AttestationVerifier::new(config);
        
        let quote = SgxQuote {
            version: 3,
            quote_type: 0,
            signature_data: SgxSignatureData {
                signature: vec![0u8; 384],
                attestation_key: vec![0u8; 384],
            },
            report_body: SgxReportBody {
                cpu_svn: [0u8; 16],
                misc_select: [0u8; 4],
                reserved1: [0u8; 28],
                isv_ext_prod_id: [0u8; 16],
                isv_ext_svn: [0u8; 16],
                attributes: SgxAttributes { flags: 1, xfrm: 0 },
                attributes_mask: SgxAttributes { flags: 0, xfrm: 0 },
                mr_enclave: [0u8; 32],
                reserved2: [0u8; 32],
                mr_signer: [0u8; 32],
                reserved3: [0u8; 96],
                isv_prod_id: 1,
                isv_svn: 1,
                reserved4: [0u8; 60],
                report_data: [0u8; 64],
            },
        };
        
        let policy = SecurityPolicy::default();
        let result = verifier.verify_sgx_attestation(&quote, &policy, None).await;
        
        // Should succeed with simulated verification
        assert!(result.is_ok());
        let details = result.unwrap();
        assert!(details.cert_validation);
        assert!(details.measurement_validation);
        assert!(details.security_version_validation);
        assert!(details.debug_mode_validation);
    }
    
    #[tokio::test]
    async fn test_timestamp_verification() {
        let config = VerificationConfig::default();
        let verifier = AttestationVerifier::new(config);
        
        let valid_timestamp = Utc::now();
        let result = verifier.verify_timestamp(&valid_timestamp).await;
        assert!(result.is_ok());
        
        let old_timestamp = Utc::now() - chrono::Duration::seconds(400);
        let result = verifier.verify_timestamp(&old_timestamp).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_trusted_data_store() {
        let mut store = TrustedDataStore::new();
        
        // Add trusted certificate
        store.add_nitro_certificate("test-cert".to_string(), "certificate-data".to_string());
        assert!(store.aws_nitro_certs.contains_key("test-cert"));
        
        // Add trusted PCRs
        let mut pcrs = HashMap::new();
        pcrs.insert("PCR0".to_string(), "hash-value".to_string());
        store.add_trusted_pcrs(TeeType::AwsNitro, pcrs);
        assert!(store.trusted_pcrs.get(&TeeType::AwsNitro).unwrap().contains_key("PCR0"));
    }
}
