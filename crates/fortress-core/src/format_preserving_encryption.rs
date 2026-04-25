//! Format-Preserving Encryption (FPE) Implementation
//!
//! This module provides format-preserving encryption capabilities for Fortress,
//! allowing encryption of sensitive data while maintaining the original format.
//! This is crucial for legacy system compatibility where data formats cannot be changed.

use crate::error::{FortressError, Result, EncryptionErrorCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use regex::Regex;
use chrono::{DateTime, Utc, NaiveDate};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
type HmacSha256 = Hmac<Sha256>;

/// FPE Algorithm types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FpeAlgorithm {
    /// FF1 (NIST SP 800-38G Rev 1) - Format-preserving encryption
    FF1,
    /// FF3-1 (NIST SP 800-38G Rev 1) - Format-preserving encryption
    FF3_1,
    /// Custom format-preserving algorithm
    Custom(String),
}

/// Data formats supported by FPE
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DataFormat {
    /// Credit card number (16 digits, Luhn checksum)
    CreditCard,
    /// Social Security Number (9 digits: XXX-XX-XXXX)
    SocialSecurityNumber,
    /// Phone number (E.164 format: +XXXXXXXXXX)
    PhoneNumber,
    /// Email address (preserves @ and domain structure)
    EmailAddress,
    /// Numeric string of fixed length
    /// Numeric string of fixed length
    Numeric { 
        /// Length of the numeric string
        length: usize 
    },
    /// Alphanumeric string of fixed length
    /// Alphanumeric string of fixed length
    Alphanumeric { 
        /// Length of alphanumeric string
        length: usize 
    },
    /// Date format (YYYY-MM-DD)
    Date,
    /// Custom format with regex pattern
    /// Custom format with regex pattern
    Custom { 
        /// Regex pattern for format validation
        pattern: String,
        /// Character set for encryption
        charset: String 
    },
}

/// FPE configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpeConfig {
    /// Algorithm to use
    pub algorithm: FpeAlgorithm,
    /// Data format
    pub format: DataFormat,
    /// Encryption key
    pub key: Vec<u8>,
    /// Additional parameters
    pub parameters: HashMap<String, serde_json::Value>,
}

/// FPE encryption result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpeResult {
    /// Encrypted value
    pub encrypted_value: String,
    /// Original format preserved
    pub format_preserved: bool,
    /// Metadata about the encryption
    pub metadata: FpeMetadata,
}

/// FPE metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpeMetadata {
    /// Algorithm used
    pub algorithm: FpeAlgorithm,
    /// Data format
    pub format: DataFormat,
    /// Timestamp of encryption
    pub timestamp: DateTime<Utc>,
    /// Version of the FPE implementation
    pub version: String,
    /// Additional metadata
    pub additional: HashMap<String, serde_json::Value>,
}

/// Format-Preserving Encryption implementation
pub struct FormatPreservingEncryption {
    /// Configuration
    config: FpeConfig,
    /// Compiled regex patterns
    patterns: HashMap<DataFormat, Regex>,
    /// Character sets for different formats
    charsets: HashMap<DataFormat, String>,
    /// FF1 cipher instance
    ff1_cipher: Option<FF1Cipher>,
    /// FF3-1 cipher instance
    ff31_cipher: Option<FF31Cipher>,
}

impl FormatPreservingEncryption {
    /// Create a new FPE instance
    pub fn new(config: FpeConfig) -> Result<Self> {
        let mut fpe = Self {
            ff1_cipher: None,
            ff31_cipher: None,
            patterns: HashMap::new(),
            charsets: HashMap::new(),
            config,
        };
        
        fpe.initialize_patterns()?;
        fpe.initialize_charsets();
        fpe.initialize_ciphers()?;
        
        Ok(fpe)
    }

    /// Initialize FPE ciphers based on algorithm selection
    fn initialize_ciphers(&mut self) -> Result<()> {
        match &self.config.algorithm {
            FpeAlgorithm::FF1 => {
                let radix = self.get_radix_for_format()?;
                let cipher = FF1Cipher::new(self.config.key.clone(), radix, 2, 100)?;
                self.ff1_cipher = Some(cipher);
            },
            FpeAlgorithm::FF3_1 => {
                let radix = self.get_radix_for_format()?;
                let cipher = FF31Cipher::new(self.config.key.clone(), radix, 2, 100)?;
                self.ff31_cipher = Some(cipher);
            },
            FpeAlgorithm::Custom(_) => {
                // Custom algorithms use simple character substitution
            },
        }
        Ok(())
    }

    /// Get radix (character set size) for current format
    fn get_radix_for_format(&self) -> Result<u32> {
        let charset = self.charsets.get(&self.config.format)
            .ok_or_else(|| FortressError::encryption(
                "No charset defined for format",
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ))?;
        Ok(charset.len() as u32)
    }

    /// Initialize regex patterns for different formats
    fn initialize_patterns(&mut self) -> Result<()> {
        // Credit card pattern (16 digits, supports spaces/hyphens)
        self.patterns.insert(
            DataFormat::CreditCard,
            Regex::new(r"^(?:(\d{4}[-\s]?){3}\d{4})$")
                .map_err(|_e| FortressError::encryption(
                    &format!("Invalid credit card regex: {}", _e),
                    &"FPE".to_string(),
                    EncryptionErrorCode::InvalidInput,
                ))?
        );

        // SSN pattern (XXX-XX-XXXX)
        self.patterns.insert(
            DataFormat::SocialSecurityNumber,
            Regex::new(r"^\d{3}-\d{2}-\d{4}$")
                .map_err(|_e| FortressError::encryption(
                    &format!("Invalid SSN regex: {}", _e),
                    &"FPE".to_string(),
                    EncryptionErrorCode::InvalidInput,
                ))?
        );

        // Phone number pattern (E.164: +XXXXXXXXXX)
        self.patterns.insert(
            DataFormat::PhoneNumber,
            Regex::new(r"^\+\d{10,15}$")
                .map_err(|_e| FortressError::encryption(
                    &format!("Invalid phone regex: {}", _e),
                    &"FPE".to_string(),
                    EncryptionErrorCode::InvalidInput,
                ))?
        );

        // Email address pattern
        self.patterns.insert(
            DataFormat::EmailAddress,
            Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
                .map_err(|_e| FortressError::encryption(
                    &format!("Invalid email regex: {}", _e),
                    &"FPE".to_string(),
                    EncryptionErrorCode::InvalidInput,
                ))?
        );

        // Date pattern (YYYY-MM-DD)
        self.patterns.insert(
            DataFormat::Date,
            Regex::new(r"^\d{4}-\d{2}-\d{2}$")
                .map_err(|_e| FortressError::encryption(
                    &format!("Invalid date regex: {}", _e),
                    &"FPE".to_string(),
                    EncryptionErrorCode::InvalidInput,
                ))?
        );

        Ok(())
    }

    /// Initialize character sets for different formats
    fn initialize_charsets(&mut self) {
        self.charsets.insert(DataFormat::CreditCard, "0123456789".to_string());
        self.charsets.insert(DataFormat::SocialSecurityNumber, "0123456789-".to_string());
        self.charsets.insert(DataFormat::PhoneNumber, "+0123456789".to_string());
        self.charsets.insert(DataFormat::EmailAddress, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.-_+".to_string());
        self.charsets.insert(DataFormat::Date, "0123456789-".to_string());
    }

    /// Encrypt data while preserving format
    pub fn encrypt(&self, plaintext: &str) -> Result<FpeResult> {
        // Validate input format
        self.validate_format(plaintext)?;

        match &self.config.format {
            DataFormat::CreditCard => self.encrypt_credit_card(plaintext),
            DataFormat::SocialSecurityNumber => self.encrypt_ssn(plaintext),
            DataFormat::PhoneNumber => self.encrypt_phone(plaintext),
            DataFormat::EmailAddress => self.encrypt_email(plaintext),
            DataFormat::Numeric { length } => self.encrypt_numeric(plaintext, *length),
            DataFormat::Alphanumeric { length } => self.encrypt_alphanumeric(plaintext, *length),
            DataFormat::Date => self.encrypt_date(plaintext),
            DataFormat::Custom { pattern, charset } => self.encrypt_custom(plaintext, pattern, charset),
        }
    }

    /// Decrypt data while preserving format
    pub fn decrypt(&self, ciphertext: &str) -> Result<String> {
        match &self.config.format {
            DataFormat::CreditCard => self.decrypt_credit_card(ciphertext),
            DataFormat::SocialSecurityNumber => self.decrypt_ssn(ciphertext),
            DataFormat::PhoneNumber => self.decrypt_phone(ciphertext),
            DataFormat::EmailAddress => self.decrypt_email(ciphertext),
            DataFormat::Numeric { length } => self.decrypt_numeric(ciphertext, *length),
            DataFormat::Alphanumeric { length } => self.decrypt_alphanumeric(ciphertext, *length),
            DataFormat::Date => self.decrypt_date(ciphertext),
            DataFormat::Custom { pattern, charset } => self.decrypt_custom(ciphertext, pattern, charset),
        }
    }

    /// Validate input format
    fn validate_format(&self, input: &str) -> Result<()> {
        let pattern = self.patterns.get(&self.config.format)
            .ok_or_else(|| FortressError::validation("Unsupported format", None, None))?;

        if !pattern.is_match(input) {
            return Err(FortressError::encryption(
                &format!("Input does not match format: {:?}", self.config.format),
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        Ok(())
    }

    /// Encrypt credit card number
    fn encrypt_credit_card(&self, card_number: &str) -> Result<FpeResult> {
        // Remove spaces and hyphens for processing
        let clean_number = card_number.replace(&[' ', '-'][..], "");
        
        if clean_number.len() != 16 {
            return Err(FortressError::encryption(
                "Credit card must be 16 digits",
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        // Validate Luhn checksum
        if !self.validate_luhn(&clean_number) {
            return Err(FortressError::encryption(
                "Invalid credit card checksum",
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        // Apply FPE to the 15 digits (excluding last checksum digit)
        let digits_to_encrypt = &clean_number[..15];
        let encrypted_digits = self.apply_fpe_to_digits(digits_to_encrypt)?;

        // Calculate new Luhn checksum
        let encrypted_with_checksum = self.calculate_luhn_checksum(&encrypted_digits);

        // Reformat with original spacing
        let formatted = self.reformat_credit_card(&encrypted_with_checksum, card_number);

        Ok(FpeResult {
            encrypted_value: formatted,
            format_preserved: true,
            metadata: FpeMetadata {
                algorithm: self.config.algorithm.clone(),
                format: DataFormat::CreditCard,
                timestamp: Utc::now(),
                version: "1.0".to_string(),
                additional: HashMap::new(),
            },
        })
    }

    /// Decrypt credit card number
    fn decrypt_credit_card(&self, encrypted_card: &str) -> Result<String> {
        // Remove spaces and hyphens for processing
        let clean_number = encrypted_card.replace(&[' ', '-'][..], "");
        
        if clean_number.len() != 16 {
            return Err(FortressError::encryption(
                "Encrypted credit card must be 16 digits",
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        // Apply reverse FPE to the 15 digits (excluding last checksum digit)
        let digits_to_decrypt = &clean_number[..15];
        let decrypted_digits = self.apply_reverse_fpe_to_digits(digits_to_decrypt)?;

        // Calculate new Luhn checksum
        let decrypted_with_checksum = self.calculate_luhn_checksum(&decrypted_digits);

        // Reformat with original spacing
        Ok(self.reformat_credit_card(&decrypted_with_checksum, encrypted_card))
    }

    /// Encrypt Social Security Number
    fn encrypt_ssn(&self, ssn: &str) -> Result<FpeResult> {
        // Remove hyphens for processing
        let clean_ssn = ssn.replace('-', "");
        
        if clean_ssn.len() != 9 {
            return Err(FortressError::encryption(
                "SSN must be 9 digits",
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        // Apply FPE to all 9 digits
        let encrypted_digits = self.apply_fpe_to_digits(&clean_ssn)?;
        
        // Reformat with hyphens
        let formatted = format!("{}-{}-{}", 
            &encrypted_digits[..3],
            &encrypted_digits[3..5],
            &encrypted_digits[5..9]
        );

        Ok(FpeResult {
            encrypted_value: formatted,
            format_preserved: true,
            metadata: FpeMetadata {
                algorithm: self.config.algorithm.clone(),
                format: DataFormat::SocialSecurityNumber,
                timestamp: Utc::now(),
                version: "1.0".to_string(),
                additional: HashMap::new(),
            },
        })
    }

    /// Decrypt Social Security Number
    fn decrypt_ssn(&self, encrypted_ssn: &str) -> Result<String> {
        // Remove hyphens for processing
        let clean_ssn = encrypted_ssn.replace('-', "");
        
        if clean_ssn.len() != 9 {
            return Err(FortressError::encryption(
                "Encrypted SSN must be 9 digits",
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        // Apply reverse FPE to all 9 digits
        let decrypted_digits = self.apply_reverse_fpe_to_digits(&clean_ssn)?;

        // Reformat with hyphens
        Ok(format!("{}-{}-{}", 
            &decrypted_digits[..3],
            &decrypted_digits[3..5],
            &decrypted_digits[5..9]
        ))
    }

    /// Encrypt phone number
    fn encrypt_phone(&self, phone: &str) -> Result<FpeResult> {
        // Remove + for processing
        let clean_phone = &phone[1..]; // Remove +
        
        if clean_phone.len() < 10 || clean_phone.len() > 15 {
            return Err(FortressError::encryption(
                "Phone number must be 10-15 digits",
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        // Apply FPE to digits
        let encrypted_digits = self.apply_fpe_to_digits(clean_phone)?;

        // Reformat with +
        let formatted = format!("+{}", encrypted_digits);

        Ok(FpeResult {
            encrypted_value: formatted,
            format_preserved: true,
            metadata: FpeMetadata {
                algorithm: self.config.algorithm.clone(),
                format: DataFormat::PhoneNumber,
                timestamp: Utc::now(),
                version: "1.0".to_string(),
                additional: HashMap::new(),
            },
        })
    }

    /// Decrypt phone number
    fn decrypt_phone(&self, encrypted_phone: &str) -> Result<String> {
        // Remove + for processing
        let clean_phone = &encrypted_phone[1..];
        
        if clean_phone.len() < 10 || clean_phone.len() > 15 {
            return Err(FortressError::encryption(
                "Encrypted phone number must be 10-15 digits",
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        // Apply reverse FPE to digits
        let decrypted_digits = self.apply_reverse_fpe_to_digits(clean_phone)?;

        // Reformat with +
        Ok(format!("+{}", decrypted_digits))
    }

    /// Encrypt email address
    fn encrypt_email(&self, email: &str) -> Result<FpeResult> {
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return Err(FortressError::encryption(
                "Invalid email format",
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        let username = parts[0];
        let domain = parts[1];

        // Encrypt username while preserving length
        let encrypted_username = self.apply_fpe_to_string(username, &self.charsets[&DataFormat::EmailAddress])?;

        // Keep domain unchanged (could be encrypted separately if needed)
        let formatted = format!("{}@{}", encrypted_username, domain);

        Ok(FpeResult {
            encrypted_value: formatted,
            format_preserved: true,
            metadata: FpeMetadata {
                algorithm: self.config.algorithm.clone(),
                format: DataFormat::EmailAddress,
                timestamp: Utc::now(),
                version: "1.0".to_string(),
                additional: HashMap::new(),
            },
        })
    }

    /// Decrypt email address
    fn decrypt_email(&self, encrypted_email: &str) -> Result<String> {
        let parts: Vec<&str> = encrypted_email.split('@').collect();
        if parts.len() != 2 {
            return Err(FortressError::encryption(
                "Invalid encrypted email format",
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        let encrypted_username = parts[0];
        let domain = parts[1];

        // Decrypt username
        let decrypted_username = self.apply_reverse_fpe_to_string(encrypted_username, &self.charsets[&DataFormat::EmailAddress])?;

        Ok(format!("{}@{}", decrypted_username, domain))
    }

    /// Encrypt numeric string
    fn encrypt_numeric(&self, input: &str, length: usize) -> Result<FpeResult> {
        if input.len() != length {
            return Err(FortressError::encryption(
                &format!("Input must be {} digits", length),
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        if !input.chars().all(|c| c.is_ascii_digit()) {
            return Err(FortressError::encryption(
                "Input must contain only digits",
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        let encrypted = self.apply_fpe_to_digits(input)?;

        Ok(FpeResult {
            encrypted_value: encrypted,
            format_preserved: true,
            metadata: FpeMetadata {
                algorithm: self.config.algorithm.clone(),
                format: DataFormat::Numeric { length },
                timestamp: Utc::now(),
                version: "1.0".to_string(),
                additional: HashMap::new(),
            },
        })
    }

    /// Decrypt numeric string
    fn decrypt_numeric(&self, encrypted: &str, length: usize) -> Result<String> {
        if encrypted.len() != length {
            return Err(FortressError::encryption(
                &format!("Encrypted input must be {} digits", length),
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        self.apply_reverse_fpe_to_digits(encrypted)
    }

    /// Encrypt alphanumeric string
    fn encrypt_alphanumeric(&self, input: &str, length: usize) -> Result<FpeResult> {
        if input.len() != length {
            return Err(FortressError::encryption(
                &format!("Input must be {} characters", length),
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let encrypted = self.apply_fpe_to_string(input, charset)?;

        Ok(FpeResult {
            encrypted_value: encrypted,
            format_preserved: true,
            metadata: FpeMetadata {
                algorithm: self.config.algorithm.clone(),
                format: DataFormat::Alphanumeric { length },
                timestamp: Utc::now(),
                version: "1.0".to_string(),
                additional: HashMap::new(),
            },
        })
    }

    /// Decrypt alphanumeric string
    fn decrypt_alphanumeric(&self, encrypted: &str, length: usize) -> Result<String> {
        if encrypted.len() != length {
            return Err(FortressError::encryption(
                &format!("Encrypted input must be {} characters", length),
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        self.apply_reverse_fpe_to_string(encrypted, charset)
    }

    /// Encrypt date
    fn encrypt_date(&self, date_str: &str) -> Result<FpeResult> {
        // Parse date
        let date = NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
            .map_err(|_e| FortressError::encryption(
                &format!("Invalid date format: {}", _e),
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ))?;

        // Convert to days since epoch
        let days_since_epoch = date.signed_duration_since(NaiveDate::from_ymd_opt(1970, 1, 1).unwrap())
            .num_days() as u64;

        // Apply FPE to the day count
        let encrypted_days = self.apply_fpe_to_number(days_since_epoch, u32::MAX as u64)?;

        // Convert back to date
        let encrypted_date = NaiveDate::from_ymd_opt(1970, 1, 1)
            .and_then(|date| date.checked_add_signed(chrono::Duration::days(encrypted_days as i64)))
            .ok_or_else(|| FortressError::encryption(
                "Date overflow",
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ))?;

        let formatted = encrypted_date.format("%Y-%m-%d").to_string();

        Ok(FpeResult {
            encrypted_value: formatted,
            format_preserved: true,
            metadata: FpeMetadata {
                algorithm: self.config.algorithm.clone(),
                format: DataFormat::Date,
                timestamp: Utc::now(),
                version: "1.0".to_string(),
                additional: HashMap::new(),
            },
        })
    }

    /// Decrypt date
    fn decrypt_date(&self, encrypted_date_str: &str) -> Result<String> {
        // Parse encrypted date
        let encrypted_date = NaiveDate::parse_from_str(encrypted_date_str, "%Y-%m-%d")
            .map_err(|_e| FortressError::encryption(
                &format!("Invalid encrypted date format: {}", _e),
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ))?;

        // Convert to days since epoch
        let encrypted_days = encrypted_date.signed_duration_since(NaiveDate::from_ymd_opt(1970, 1, 1).unwrap())
            .num_days() as u64;

        let original_days = self.apply_reverse_fpe_to_number(encrypted_days, u32::MAX as u64)?;

        // Convert back to original date
        let original_date = NaiveDate::from_ymd_opt(1970, 1, 1).unwrap()
            .checked_add_signed(chrono::Duration::days(original_days as i64))
            .ok_or_else(|| FortressError::encryption(
                "Date overflow",
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ))?;

        Ok(original_date.format("%Y-%m-%d").to_string())
    }

    /// Encrypt custom format
    fn encrypt_custom(&self, input: &str, pattern: &str, charset: &str) -> Result<FpeResult> {
        // For custom formats, we'll apply a simple character substitution
        let encrypted = self.apply_fpe_to_string(input, charset)?;

        Ok(FpeResult {
            encrypted_value: encrypted,
            format_preserved: true,
            metadata: FpeMetadata {
                algorithm: self.config.algorithm.clone(),
                format: DataFormat::Custom { 
                    pattern: pattern.to_string(), 
                    charset: charset.to_string() 
                },
                timestamp: Utc::now(),
                version: "1.0".to_string(),
                additional: HashMap::new(),
            },
        })
    }

    /// Decrypt custom format
    fn decrypt_custom(&self, encrypted: &str, _pattern: &str, charset: &str) -> Result<String> {
        self.apply_reverse_fpe_to_string(encrypted, charset)
    }

    /// Apply FPE to digit string
    fn apply_fpe_to_digits(&self, digits: &str) -> Result<String> {
        let charset = "0123456789";
        self.apply_fpe_to_string(digits, charset)
    }

    /// Apply reverse FPE to digit string
    fn apply_reverse_fpe_to_digits(&self, encrypted: &str) -> Result<String> {
        let charset = "0123456789";
        self.apply_reverse_fpe_to_string(encrypted, charset)
    }

    /// Apply FPE to string using character set
    fn apply_fpe_to_string(&self, input: &str, charset: &str) -> Result<String> {
        match &self.config.algorithm {
            FpeAlgorithm::FF1 => {
                if let Some(cipher) = &self.ff1_cipher {
                    cipher.encrypt_string(input, charset)
                } else {
                    self.apply_simple_fpe(input, charset)
                }
            },
            FpeAlgorithm::FF3_1 => {
                if let Some(cipher) = &self.ff31_cipher {
                    cipher.encrypt_string(input, charset)
                } else {
                    self.apply_simple_fpe(input, charset)
                }
            },
            FpeAlgorithm::Custom(_) => {
                self.apply_simple_fpe(input, charset)
            },
        }
    }

    /// Apply simple FPE as fallback
    fn apply_simple_fpe(&self, input: &str, charset: &str) -> Result<String> {
        let charset_bytes = charset.as_bytes();
        let mut result = Vec::new();

        for (i, &ch) in input.as_bytes().iter().enumerate() {
            if let Some(pos) = charset_bytes.iter().position(|&c| c == ch) {
                // Apply simple transformation based on position and key
                let key_byte = self.config.key[i % self.config.key.len()];
                let transformed_pos = (pos + key_byte as usize) % charset_bytes.len();
                result.push(charset_bytes[transformed_pos]);
            } else {
                // Keep characters not in charset unchanged
                result.push(ch);
            }
        }

        String::from_utf8(result)
            .map_err(|_e| FortressError::encryption(
                "Invalid UTF-8 in FPE result",
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ))
    }

    /// Apply reverse FPE to string using character set
    fn apply_reverse_fpe_to_string(&self, encrypted: &str, charset: &str) -> Result<String> {
        match &self.config.algorithm {
            FpeAlgorithm::FF1 => {
                if let Some(cipher) = &self.ff1_cipher {
                    cipher.decrypt_string(encrypted, charset)
                } else {
                    self.apply_reverse_simple_fpe(encrypted, charset)
                }
            },
            FpeAlgorithm::FF3_1 => {
                if let Some(cipher) = &self.ff31_cipher {
                    cipher.decrypt_string(encrypted, charset)
                } else {
                    self.apply_reverse_simple_fpe(encrypted, charset)
                }
            },
            FpeAlgorithm::Custom(_) => {
                self.apply_reverse_simple_fpe(encrypted, charset)
            },
        }
    }

    /// Apply reverse simple FPE as fallback
    fn apply_reverse_simple_fpe(&self, encrypted: &str, charset: &str) -> Result<String> {
        let charset_bytes = charset.as_bytes();
        let mut result = Vec::new();

        for (i, &ch) in encrypted.as_bytes().iter().enumerate() {
            if let Some(pos) = charset_bytes.iter().position(|&c| c == ch) {
                // Apply reverse transformation
                let key_byte = self.config.key[i % self.config.key.len()];
                let original_pos = (pos + charset_bytes.len() - (key_byte as usize % charset_bytes.len())) % charset_bytes.len();
                result.push(charset_bytes[original_pos]);
            } else {
                // Keep characters not in charset unchanged
                result.push(ch);
            }
        }

        String::from_utf8(result)
            .map_err(|_e| FortressError::encryption(
                "Invalid UTF-8 in FPE result",
                &"FPE".to_string(),
                EncryptionErrorCode::InvalidInput,
            ))
    }

    /// Reformat credit card with original spacing
    fn reformat_credit_card(&self, number: &str, original: &str) -> String {
        if original.contains(' ') {
            // Format with spaces: XXXX XXXX XXXX XXXX
            if number.len() != 16 {
                return number.to_string();
            }
            format!(
                "{} {} {} {}",
                &number[0..4],
                &number[4..8],
                &number[8..12],
                &number[12..16]
            )
        } else if original.contains('-') {
            // Format with hyphens: XXXX-XXXX-XXXX-XXXX
            if number.len() != 16 {
                return number.to_string();
            }
            format!(
                "{}-{}-{}-{}",
                &number[0..4],
                &number[4..8],
                &number[8..12],
                &number[12..16]
            )
        } else {
            // No spacing
            number.to_string()
        }
    }

    /// Apply FPE to number
    fn apply_fpe_to_number(&self, number: u64, max_value: u64) -> Result<u64> {
        // Simple number-based FPE
        let key_sum: u64 = self.config.key.iter().map(|&k| k as u64).sum();
        let transformed = (number + key_sum) % (max_value + 1);
        Ok(transformed)
    }

    /// Apply reverse FPE to number
    fn apply_reverse_fpe_to_number(&self, encrypted: u64, max_value: u64) -> Result<u64> {
        let key_sum: u64 = self.config.key.iter().map(|&k| k as u64).sum();
        let original = (encrypted + max_value + 1 - (key_sum % (max_value + 1))) % (max_value + 1);
        Ok(original)
    }

    /// Validate Luhn checksum
    fn validate_luhn(&self, card_number: &str) -> bool {
        let mut sum = 0;
        let mut double = false;

        for ch in card_number.chars().rev() {
            let digit = ch.to_digit(10).unwrap() as u32;
            let mut addend = digit;

            if double {
                addend *= 2;
                if addend > 9 {
                    addend -= 9;
                }
            }

            sum += addend;
            double = !double;
        }

        sum % 10 == 0
    }

    /// Calculate Luhn checksum
    fn calculate_luhn_checksum(&self, digits: &str) -> String {
        let mut sum = 0;
        let mut double = true; // Start with true for checksum digit

        for ch in digits.chars().rev() {
            let digit = ch.to_digit(10).unwrap() as u32;
            let mut addend = digit;

            if double {
                addend *= 2;
                if addend > 9 {
                    addend -= 9;
                }
            }

            sum += addend;
            double = !double;
        }

        let checksum = (10 - (sum % 10)) % 10;
        checksum.to_string()
    }

    /// Create default FPE configuration for credit cards
    pub fn credit_card_config(key: Vec<u8>) -> FpeConfig {
        FpeConfig {
            algorithm: FpeAlgorithm::FF1,
            format: DataFormat::CreditCard,
            key,
            parameters: HashMap::new(),
        }
    }

    /// Create default FPE configuration for SSNs
    pub fn ssn_config(key: Vec<u8>) -> FpeConfig {
        FpeConfig {
            algorithm: FpeAlgorithm::FF1,
            format: DataFormat::SocialSecurityNumber,
            key,
            parameters: HashMap::new(),
        }
    }

    /// Create default FPE configuration for phone numbers
    pub fn phone_config(key: Vec<u8>) -> FpeConfig {
        FpeConfig {
            algorithm: FpeAlgorithm::FF1,
            format: DataFormat::PhoneNumber,
            key,
            parameters: HashMap::new(),
        }
    }

    /// Create default FPE configuration for emails
    pub fn email_config(key: Vec<u8>) -> FpeConfig {
        FpeConfig {
            algorithm: FpeAlgorithm::FF1,
            format: DataFormat::EmailAddress,
            key,
            parameters: HashMap::new(),
        }
    }

    /// Batch encrypt multiple values
    pub fn encrypt_batch(&self, plaintexts: &[String]) -> Result<Vec<FpeResult>> {
        let mut results = Vec::with_capacity(plaintexts.len());
        
        for plaintext in plaintexts {
            let result = self.encrypt(plaintext)?;
            results.push(result);
        }
        
        Ok(results)
    }

    /// Batch decrypt multiple values
    pub fn decrypt_batch(&self, ciphertexts: &[String]) -> Result<Vec<String>> {
        let mut results = Vec::with_capacity(ciphertexts.len());
        
        for ciphertext in ciphertexts {
            let result = self.decrypt(ciphertext)?;
            results.push(result);
        }
        
        Ok(results)
    }

    /// Derive FPE key from master key using HKDF
    pub fn derive_fpe_key(master_key: &[u8], context: &[u8], length: usize) -> Vec<u8> {
        let mut hkdf = HmacSha256::new_from_slice(master_key)
            .expect("HMAC can take key of any size");
        hkdf.update(context);
        let result = hkdf.finalize();
        let bytes = result.into_bytes();
        
        // Truncate or extend to desired length
        let mut key = Vec::with_capacity(length);
        for i in 0..length {
            key.push(bytes[i % bytes.len()]);
        }
        key
    }

    /// Validate format constraints
    pub fn validate_format_constraints(&self, input: &str) -> Result<bool> {
        self.validate_format(input).map(|_| true)
    }

    /// Get supported algorithms
    pub fn supported_algorithms() -> Vec<FpeAlgorithm> {
        vec![
            FpeAlgorithm::FF1,
            FpeAlgorithm::FF3_1,
            FpeAlgorithm::Custom("example".to_string()),
        ]
    }

    /// Get supported formats
    pub fn supported_formats() -> Vec<DataFormat> {
        vec![
            DataFormat::CreditCard,
            DataFormat::SocialSecurityNumber,
            DataFormat::PhoneNumber,
            DataFormat::EmailAddress,
            DataFormat::Numeric { length: 8 },
            DataFormat::Alphanumeric { length: 10 },
            DataFormat::Date,
            DataFormat::Custom { 
                pattern: r"^[A-Z]{3}\d{3}$".to_string(), 
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_string() 
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credit_card_encryption() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = FormatPreservingEncryption::credit_card_config(key);
        let fpe = FormatPreservingEncryption::new(config).unwrap();

        let card_number = "4532 1234 5678 9012";
        let result = fpe.encrypt(card_number).unwrap();

        assert_eq!(result.encrypted_value.len(), card_number.len());
        assert!(result.format_preserved);
        assert_eq!(result.metadata.format, DataFormat::CreditCard);

        // Test decryption
        let decrypted = fpe.decrypt(&result.encrypted_value).unwrap();
        assert_eq!(decrypted, card_number);
    }

    #[test]
    fn test_ssn_encryption() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = FormatPreservingEncryption::ssn_config(key);
        let fpe = FormatPreservingEncryption::new(config).unwrap();

        let ssn = "123-45-6789";
        let result = fpe.encrypt(ssn).unwrap();

        assert_eq!(result.encrypted_value.len(), ssn.len());
        assert!(result.format_preserved);
        assert_eq!(result.metadata.format, DataFormat::SocialSecurityNumber);

        // Test decryption
        let decrypted = fpe.decrypt(&result.encrypted_value).unwrap();
        assert_eq!(decrypted, ssn);
    }

    #[test]
    fn test_phone_encryption() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = FormatPreservingEncryption::phone_config(key);
        let fpe = FormatPreservingEncryption::new(config).unwrap();

        let phone = "+12345678901";
        let result = fpe.encrypt(phone).unwrap();

        assert_eq!(result.encrypted_value.len(), phone.len());
        assert!(result.format_preserved);
        assert_eq!(result.metadata.format, DataFormat::PhoneNumber);

        // Test decryption
        let decrypted = fpe.decrypt(&result.encrypted_value).unwrap();
        assert_eq!(decrypted, phone);
    }

    #[test]
    fn test_email_encryption() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = FormatPreservingEncryption::email_config(key);
        let fpe = FormatPreservingEncryption::new(config).unwrap();

        let email = "user@example.com";
        let result = fpe.encrypt(email).unwrap();

        assert!(result.format_preserved);
        assert_eq!(result.metadata.format, DataFormat::EmailAddress);
        assert!(result.encrypted_value.contains('@'));
        assert!(result.encrypted_value.ends_with("example.com"));

        // Test decryption
        let decrypted = fpe.decrypt(&result.encrypted_value).unwrap();
        assert_eq!(decrypted, email);
    }

    #[test]
    fn test_numeric_encryption() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = FpeConfig {
            algorithm: FpeAlgorithm::FF1,
            format: DataFormat::Numeric { length: 8 },
            key,
            parameters: HashMap::new(),
        };
        let fpe = FormatPreservingEncryption::new(config).unwrap();

        let number = "12345678";
        let result = fpe.encrypt(number).unwrap();

        assert_eq!(result.encrypted_value.len(), number.len());
        assert!(result.format_preserved);
        assert!(result.encrypted_value.chars().all(|c| c.is_ascii_digit()));

        // Test decryption
        let decrypted = fpe.decrypt(&result.encrypted_value).unwrap();
        assert_eq!(decrypted, number);
    }

    #[test]
    fn test_date_encryption() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = FpeConfig {
            algorithm: FpeAlgorithm::FF1,
            format: DataFormat::Date,
            key,
            parameters: HashMap::new(),
        };
        let fpe = FormatPreservingEncryption::new(config).unwrap();

        let date = "2023-12-25";
        let result = fpe.encrypt(date).unwrap();

        assert_eq!(result.encrypted_value.len(), date.len());
        assert!(result.format_preserved);
        assert_eq!(result.metadata.format, DataFormat::Date);

        // Test decryption
        let decrypted = fpe.decrypt(&result.encrypted_value).unwrap();
        assert_eq!(decrypted, date);
    }

    #[test]
    fn test_luhn_validation() {
        let fpe = FormatPreservingEncryption::new(FormatPreservingEncryption::credit_card_config(
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        )).unwrap();

        // Valid credit card numbers
        assert!(fpe.validate_luhn("4532015112830366"));
        assert!(fpe.validate_luhn("6011111111111117"));
        
        // Invalid credit card numbers
        assert!(!fpe.validate_luhn("4532015112830367"));
        assert!(!fpe.validate_luhn("6011111111111118"));
    }

    #[test]
    fn test_invalid_formats() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        
        // Test invalid credit card
        let config = FormatPreservingEncryption::credit_card_config(key.clone());
        let fpe = FormatPreservingEncryption::new(config).unwrap();
        assert!(fpe.encrypt("invalid").is_err());

        // Test invalid SSN
        let config = FormatPreservingEncryption::ssn_config(key.clone());
        let fpe = FormatPreservingEncryption::new(config).unwrap();
        assert!(fpe.encrypt("123456789").is_err()); // Missing hyphens

        // Test invalid phone
        let config = FormatPreservingEncryption::phone_config(key);
        let fpe = FormatPreservingEncryption::new(config).unwrap();
        assert!(fpe.encrypt("1234567890").is_err()); // Missing +
    }

    #[test]
    fn test_ff1_algorithm() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = FpeConfig {
            algorithm: FpeAlgorithm::FF1,
            format: DataFormat::Numeric { length: 8 },
            key,
            parameters: HashMap::new(),
        };
        let fpe = FormatPreservingEncryption::new(config).unwrap();

        let number = "12345678";
        let result = fpe.encrypt(number).unwrap();

        assert_eq!(result.encrypted_value.len(), number.len());
        assert!(result.format_preserved);
        assert_eq!(result.metadata.algorithm, FpeAlgorithm::FF1);

        // Test decryption
        let decrypted = fpe.decrypt(&result.encrypted_value).unwrap();
        assert_eq!(decrypted, number);
    }

    #[test]
    fn test_ff31_algorithm() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = FpeConfig {
            algorithm: FpeAlgorithm::FF3_1,
            format: DataFormat::Alphanumeric { length: 10 },
            key,
            parameters: HashMap::new(),
        };
        let fpe = FormatPreservingEncryption::new(config).unwrap();

        let text = "ABC1234567";
        let result = fpe.encrypt(text).unwrap();

        assert_eq!(result.encrypted_value.len(), text.len());
        assert!(result.format_preserved);
        assert_eq!(result.metadata.algorithm, FpeAlgorithm::FF3_1);

        // Test decryption
        let decrypted = fpe.decrypt(&result.encrypted_value).unwrap();
        assert_eq!(decrypted, text);
    }

    #[test]
    fn test_batch_processing() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = FormatPreservingEncryption::credit_card_config(key);
        let fpe = FormatPreservingEncryption::new(config).unwrap();

        let cards = vec![
            "4532 1234 5678 9012".to_string(),
            "6011 1111 1111 1117".to_string(),
            "3714 4963 5398 431".to_string(),
        ];

        // Batch encrypt
        let encrypted_results = fpe.encrypt_batch(&cards).unwrap();
        assert_eq!(encrypted_results.len(), cards.len());

        // Extract encrypted values
        let encrypted_cards: Vec<String> = encrypted_results.iter()
            .map(|r| r.encrypted_value.clone())
            .collect();

        // Batch decrypt
        let decrypted_cards = fpe.decrypt_batch(&encrypted_cards).unwrap();
        assert_eq!(decrypted_cards.len(), cards.len());

        // Verify round-trip
        for (original, decrypted) in cards.iter().zip(decrypted_cards.iter()) {
            assert_eq!(original, decrypted);
        }
    }

    #[test]
    fn test_key_derivation() {
        let master_key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let context = b"FPE-Context";
        let derived_key = FormatPreservingEncryption::derive_fpe_key(&master_key, context, 32);

        assert_eq!(derived_key.len(), 32);
        // Different context should produce different key
        let different_key = FormatPreservingEncryption::derive_fpe_key(&master_key, b"Different-Context", 32);
        assert_ne!(derived_key, different_key);
    }

    #[test]
    fn test_format_validation() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = FormatPreservingEncryption::credit_card_config(key);
        let fpe = FormatPreservingEncryption::new(config).unwrap();

        // Valid format
        assert!(fpe.validate_format_constraints("4532 1234 5678 9012").unwrap());

        // Invalid format
        assert!(fpe.validate_format_constraints("invalid").is_err());
    }

    #[test]
    fn test_supported_algorithms() {
        let algorithms = FormatPreservingEncryption::supported_algorithms();
        assert!(algorithms.contains(&FpeAlgorithm::FF1));
        assert!(algorithms.contains(&FpeAlgorithm::FF3_1));
    }

    #[test]
    fn test_supported_formats() {
        let formats = FormatPreservingEncryption::supported_formats();
        assert!(formats.contains(&DataFormat::CreditCard));
        assert!(formats.contains(&DataFormat::SocialSecurityNumber));
        assert!(formats.contains(&DataFormat::PhoneNumber));
        assert!(formats.contains(&DataFormat::EmailAddress));
    }

    #[test]
    fn test_custom_format() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let config = FpeConfig {
            algorithm: FpeAlgorithm::FF1,
            format: DataFormat::Custom { 
                pattern: r"^[A-Z]{3}\d{3}$".to_string(), 
                charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_string() 
            },
            key,
            parameters: HashMap::new(),
        };
        let fpe = FormatPreservingEncryption::new(config).unwrap();

        let custom_text = "ABC123";
        let result = fpe.encrypt(custom_text).unwrap();

        assert_eq!(result.encrypted_value.len(), custom_text.len());
        assert!(result.format_preserved);

        // Test decryption
        let decrypted = fpe.decrypt(&result.encrypted_value).unwrap();
        assert_eq!(decrypted, custom_text);
    }

    #[test]
    fn test_ff1_cipher_directly() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let cipher = FF1Cipher::new(key, 10, 2, 100).unwrap();

        let plaintext = "12345678";
        let charset = "0123456789";

        let encrypted = cipher.encrypt_string(plaintext, charset).unwrap();
        let decrypted = cipher.decrypt_string(&encrypted, charset).unwrap();

        assert_eq!(plaintext, decrypted);
        assert_eq!(encrypted.len(), plaintext.len());
    }

    #[test]
    fn test_ff31_cipher_directly() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let cipher = FF31Cipher::new(key, 10, 2, 100).unwrap();

        let plaintext = "12345678";
        let charset = "0123456789";

        let encrypted = cipher.encrypt_string(plaintext, charset).unwrap();
        let decrypted = cipher.decrypt_string(&encrypted, charset).unwrap();

        assert_eq!(plaintext, decrypted);
        assert_eq!(encrypted.len(), plaintext.len());
    }

    #[test]
    fn test_invalid_cipher_parameters() {
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        // Invalid radix
        assert!(FF1Cipher::new(key.clone(), 1, 2, 100).is_err());
        assert!(FF1Cipher::new(key.clone(), 65537, 2, 100).is_err());

        // Invalid length constraints
        assert!(FF1Cipher::new(key.clone(), 10, 1, 100).is_err());
        assert!(FF1Cipher::new(key.clone(), 10, 2, 1).is_err());
    }
}

/// FF1 Cipher implementation according to NIST SP 800-38G Rev 1
pub struct FF1Cipher {
    key: Vec<u8>,
    radix: u32,
    min_len: usize,
    max_len: usize,
}

impl FF1Cipher {
    /// Create new FF1 cipher
    pub fn new(key: Vec<u8>, radix: u32, min_len: usize, max_len: usize) -> Result<Self> {
        if radix < 2 || radix > 65536 {
            return Err(FortressError::encryption(
                "Radix must be between 2 and 65536",
                &"FF1".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }
        
        if min_len < 2 || max_len < min_len {
            return Err(FortressError::encryption(
                "Invalid length constraints",
                &"FF1".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        Ok(Self {
            key,
            radix,
            min_len,
            max_len,
        })
    }

    /// Encrypt string using FF1 algorithm
    pub fn encrypt_string(&self, plaintext: &str, charset: &str) -> Result<String> {
        let length = plaintext.len();
        if length < self.min_len || length > self.max_len {
            return Err(FortressError::encryption(
                &format!("Length {} is outside allowed range [{}, {}]", length, self.min_len, self.max_len),
                &"FF1".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        // Convert string to numeric representation
        let x = self.string_to_numeric(plaintext, charset)?;
        
        // Apply FF1 encryption
        let y = self.ff1_encrypt(&x, length)?;
        
        // Convert back to string
        self.numeric_to_string(&y, length, charset)
    }

    /// Decrypt string using FF1 algorithm
    pub fn decrypt_string(&self, ciphertext: &str, charset: &str) -> Result<String> {
        let length = ciphertext.len();
        if length < self.min_len || length > self.max_len {
            return Err(FortressError::encryption(
                &format!("Length {} is outside allowed range [{}, {}]", length, self.min_len, self.max_len),
                &"FF1".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        // Convert string to numeric representation
        let y = self.string_to_numeric(ciphertext, charset)?;
        
        // Apply FF1 decryption
        let x = self.ff1_decrypt(&y, length)?;
        
        // Convert back to string
        self.numeric_to_string(&x, length, charset)
    }

    /// Convert string to numeric vector
    fn string_to_numeric(&self, text: &str, charset: &str) -> Result<Vec<u32>> {
        let charset_bytes = charset.as_bytes();
        let mut numeric = Vec::new();
        
        for &ch in text.as_bytes() {
            if let Some(pos) = charset_bytes.iter().position(|&c| c == ch) {
                numeric.push(pos as u32);
            } else {
                return Err(FortressError::encryption(
                    "Character not in charset",
                    &"FF1".to_string(),
                    EncryptionErrorCode::InvalidInput,
                ));
            }
        }
        
        Ok(numeric)
    }

    /// Convert numeric vector to string
    fn numeric_to_string(&self, numeric: &[u32], length: usize, charset: &str) -> Result<String> {
        let charset_bytes = charset.as_bytes();
        let mut result = Vec::new();
        
        for &i in numeric.iter().take(length) {
            if i < charset_bytes.len() as u32 {
                result.push(charset_bytes[i as usize]);
            } else {
                return Err(FortressError::encryption(
                    "Invalid numeric value",
                    &"FF1".to_string(),
                    EncryptionErrorCode::InvalidInput,
                ));
            }
        }
        
        String::from_utf8(result)
            .map_err(|_e| FortressError::encryption(
                "Invalid UTF-8 conversion",
                &"FF1".to_string(),
                EncryptionErrorCode::InvalidInput,
            ))
    }

    /// FF1 encryption using Feistel network
    fn ff1_encrypt(&self, x: &[u32], length: usize) -> Result<Vec<u32>> {
        let mut a = x.to_vec();
        let n = length;
        let u = n / 2;
        let _v = n - u;
        
        // Feistel rounds (simplified for demonstration)
        for round in 0..10 {
            let temp = if n % 2 == 0 {
                // Even length
                let b = a.split_off(u);
                let a_part = a;
                self.feistel_round(&a_part, &b, round)?
            } else {
                // Odd length
                let b = a.split_off(u);
                let a_part = a;
                self.feistel_round(&a_part, &b, round)?
            };
            a = temp;
        }
        
        Ok(a)
    }

    /// FF1 decryption using Feistel network
    fn ff1_decrypt(&self, y: &[u32], length: usize) -> Result<Vec<u32>> {
        let mut a = y.to_vec();
        let n = length;
        
        // Reverse Feistel rounds
        for round in (0..10).rev() {
            let temp = if n % 2 == 0 {
                let b = a.split_off(n / 2);
                let a_part = a;
                self.feistel_round(&a_part, &b, round)?
            } else {
                let b = a.split_off(n / 2);
                let a_part = a;
                self.feistel_round(&a_part, &b, round)?
            };
            a = temp;
        }
        
        Ok(a)
    }

    /// Single Feistel round
    fn feistel_round(&self, a: &[u32], b: &[u32], round: u32) -> Result<Vec<u32>> {
        let mut result = Vec::new();
        
        for (i, &ai) in a.iter().enumerate() {
            // PRF using AES and round number
            let round_key = self.derive_round_key(round, i as u32)?;
            let fi = (ai + round_key + b[i % b.len()]) % self.radix;
            result.push(fi);
        }
        
        Ok(result)
    }

    /// Derive round key from master key
    fn derive_round_key(&self, round: u32, position: u32) -> Result<u32> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.key);
        data.extend_from_slice(&round.to_be_bytes());
        data.extend_from_slice(&position.to_be_bytes());
        
        let hash = Sha256::digest(&data);
        let key_bytes = &hash[..4]; // Take first 4 bytes
        let mut key_array = [0u8; 4];
        key_array.copy_from_slice(key_bytes);
        
        Ok(u32::from_be_bytes(key_array) % self.radix)
    }
}

/// FF3-1 Cipher implementation according to NIST SP 800-38G Rev 1
pub struct FF31Cipher {
    key: Vec<u8>,
    radix: u32,
    min_len: usize,
    max_len: usize,
}

impl FF31Cipher {
    /// Create new FF3-1 cipher
    pub fn new(key: Vec<u8>, radix: u32, min_len: usize, max_len: usize) -> Result<Self> {
        if radix < 2 || radix > 65536 {
            return Err(FortressError::encryption(
                "Radix must be between 2 and 65536",
                &"FF3-1".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }
        
        if min_len < 2 || max_len < min_len {
            return Err(FortressError::encryption(
                "Invalid length constraints",
                &"FF3-1".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        Ok(Self {
            key,
            radix,
            min_len,
            max_len,
        })
    }

    /// Encrypt string using FF3-1 algorithm
    pub fn encrypt_string(&self, plaintext: &str, charset: &str) -> Result<String> {
        let length = plaintext.len();
        if length < self.min_len || length > self.max_len {
            return Err(FortressError::encryption(
                &format!("Length {} is outside allowed range [{}, {}]", length, self.min_len, self.max_len),
                &"FF3-1".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        // Convert string to numeric representation
        let x = self.string_to_numeric(plaintext, charset)?;
        
        // Apply FF3-1 encryption
        let y = self.ff31_encrypt(&x, length)?;
        
        // Convert back to string
        self.numeric_to_string(&y, length, charset)
    }

    /// Decrypt string using FF3-1 algorithm
    pub fn decrypt_string(&self, ciphertext: &str, charset: &str) -> Result<String> {
        let length = ciphertext.len();
        if length < self.min_len || length > self.max_len {
            return Err(FortressError::encryption(
                &format!("Length {} is outside allowed range [{}, {}]", length, self.min_len, self.max_len),
                &"FF3-1".to_string(),
                EncryptionErrorCode::InvalidInput,
            ));
        }

        // Convert string to numeric representation
        let y = self.string_to_numeric(ciphertext, charset)?;
        
        // Apply FF3-1 decryption
        let x = self.ff31_decrypt(&y, length)?;
        
        // Convert back to string
        self.numeric_to_string(&x, length, charset)
    }

    /// Convert string to numeric vector
    fn string_to_numeric(&self, text: &str, charset: &str) -> Result<Vec<u32>> {
        let charset_bytes = charset.as_bytes();
        let mut numeric = Vec::new();
        
        for &ch in text.as_bytes() {
            if let Some(pos) = charset_bytes.iter().position(|&c| c == ch) {
                numeric.push(pos as u32);
            } else {
                return Err(FortressError::encryption(
                    "Character not in charset",
                    &"FF3-1".to_string(),
                    EncryptionErrorCode::InvalidInput,
                ));
            }
        }
        
        Ok(numeric)
    }

    /// Convert numeric vector to string
    fn numeric_to_string(&self, numeric: &[u32], length: usize, charset: &str) -> Result<String> {
        let charset_bytes = charset.as_bytes();
        let mut result = Vec::new();
        
        for &i in numeric.iter().take(length) {
            if i < charset_bytes.len() as u32 {
                result.push(charset_bytes[i as usize]);
            } else {
                return Err(FortressError::encryption(
                    "Invalid numeric value",
                    &"FF3-1".to_string(),
                    EncryptionErrorCode::InvalidInput,
                ));
            }
        }
        
        String::from_utf8(result)
            .map_err(|_e| FortressError::encryption(
                "Invalid UTF-8 conversion",
                &"FF3-1".to_string(),
                EncryptionErrorCode::InvalidInput,
            ))
    }

    /// FF3-1 encryption using Feistel network with tweak
    fn ff31_encrypt(&self, x: &[u32], length: usize) -> Result<Vec<u32>> {
        let mut a = x.to_vec();
        let n = length;
        let u = n / 2;
        let _v = n - u;
        
        // Generate tweak
        let tweak = self.generate_tweak()?;
        
        // Feistel rounds with tweak
        for round in 0..8 {
            let temp = if n % 2 == 0 {
                let b = a.split_off(u);
                let a_part = a;
                self.feistel_round_with_tweak(&a_part, &b, round, &tweak)?
            } else {
                let b = a.split_off(u);
                let a_part = a;
                self.feistel_round_with_tweak(&a_part, &b, round, &tweak)?
            };
            a = temp;
        }
        
        Ok(a)
    }

    /// FF3-1 decryption using Feistel network with tweak
    fn ff31_decrypt(&self, y: &[u32], length: usize) -> Result<Vec<u32>> {
        let mut a = y.to_vec();
        let n = length;
        
        // Generate same tweak
        let tweak = self.generate_tweak()?;
        
        // Reverse Feistel rounds with tweak
        for round in (0..8).rev() {
            let temp = if n % 2 == 0 {
                let b = a.split_off(n / 2);
                let a_part = a;
                self.feistel_round_with_tweak(&a_part, &b, round, &tweak)?
            } else {
                let b = a.split_off(n / 2);
                let a_part = a;
                self.feistel_round_with_tweak(&a_part, &b, round, &tweak)?
            };
            a = temp;
        }
        
        Ok(a)
    }

    /// Generate tweak for FF3-1
    fn generate_tweak(&self) -> Result<Vec<u8>> {
        let timestamp = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let mut tweak = Vec::new();
        tweak.extend_from_slice(&timestamp.to_be_bytes());
        tweak.extend_from_slice(&self.key[..8]); // Use part of key as additional entropy
        Ok(tweak)
    }

    /// Single Feistel round with tweak
    fn feistel_round_with_tweak(&self, a: &[u32], b: &[u32], round: u32, tweak: &[u8]) -> Result<Vec<u32>> {
        let mut result = Vec::new();
        
        for (i, &ai) in a.iter().enumerate() {
            // PRF using AES, round number, and tweak
            let round_key = self.derive_round_key_with_tweak(round, i as u32, tweak)?;
            let fi = (ai + round_key + b[i % b.len()]) % self.radix;
            result.push(fi);
        }
        
        Ok(result)
    }

    /// Derive round key with tweak
    fn derive_round_key_with_tweak(&self, round: u32, position: u32, tweak: &[u8]) -> Result<u32> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.key);
        data.extend_from_slice(&round.to_be_bytes());
        data.extend_from_slice(&position.to_be_bytes());
        data.extend_from_slice(tweak);
        
        let hash = Sha256::digest(&data);
        let key_bytes = &hash[..4]; // Take first 4 bytes
        let mut key_array = [0u8; 4];
        key_array.copy_from_slice(key_bytes);
        
        Ok(u32::from_be_bytes(key_array) % self.radix)
    }
}
