//! Encryption algorithms and operations for JavaScript/TypeScript bindings

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use js_sys::{Promise, Uint8Array, Object};
use serde_wasm_bindgen::{to_value, from_value};

use fortress_core::prelude::*;
use fortress_core::encryption::{EncryptionProfile, Aegis256, ChaCha20Poly1305, Aes256Gcm};
use crate::{IntoJsResult, console_log, console_error};

/// JavaScript wrapper for encryption algorithms
#[wasm_bindgen]
pub struct EncryptionAlgorithm {
    algorithm: Box<dyn EncryptionAlgorithm + Send + Sync>,
}

#[wasm_bindgen]
impl EncryptionAlgorithm {
    /// Create a new AEGIS-256 encryption algorithm
    #[wasm_bindgen(js_name = aegis256)]
    pub fn aegis256() -> EncryptionAlgorithm {
        console_log!("Creating AEGIS-256 encryption algorithm");
        EncryptionAlgorithm {
            algorithm: Box::new(Aegis256::new()),
        }
    }

    /// Create a new ChaCha20-Poly1305 encryption algorithm
    #[wasm_bindgen(js_name = chacha20poly1305)]
    pub fn chacha20poly1305() -> EncryptionAlgorithm {
        console_log!("Creating ChaCha20-Poly1305 encryption algorithm");
        EncryptionAlgorithm {
            algorithm: Box::new(ChaCha20Poly1305::new()),
        }
    }

    /// Create a new AES-256-GCM encryption algorithm
    #[wasm_bindgen(js_name = aes256gcm)]
    pub fn aes256gcm() -> EncryptionAlgorithm {
        console_log!("Creating AES-256-GCM encryption algorithm");
        EncryptionAlgorithm {
            algorithm: Box::new(Aes256Gcm::new()),
        }
    }

    /// Encrypt data
    #[wasm_bindgen(js_name = encrypt)]
    pub fn encrypt(&self, plaintext: &Uint8Array, key: &Uint8Array) -> Result<Promise, JsValue> {
        console_log!("Starting encryption of {} bytes", plaintext.length());
        
        let plaintext_data = plaintext.to_vec();
        let key_data = key.to_vec();
        
        let algorithm = self.algorithm.clone();
        
        let future = async move {
            match algorithm.encrypt(&plaintext_data, &key_data) {
                Ok(ciphertext) => {
                    console_log!("Encryption successful, {} bytes", ciphertext.len());
                    let result = Uint8Array::from(&ciphertext[..]);
                    Ok(JsValue::from(result))
                }
                Err(e) => {
                    console_error!("Encryption failed: {}", e);
                    Err(JsValue::from(e))
                }
            }
        };
        
        Ok(future_to_promise(future))
    }

    /// Decrypt data
    #[wasm_bindgen(js_name = decrypt)]
    pub fn decrypt(&self, ciphertext: &Uint8Array, key: &Uint8Array) -> Result<Promise, JsValue> {
        console_log!("Starting decryption of {} bytes", ciphertext.length());
        
        let ciphertext_data = ciphertext.to_vec();
        let key_data = key.to_vec();
        
        let algorithm = self.algorithm.clone();
        
        let future = async move {
            match algorithm.decrypt(&ciphertext_data, &key_data) {
                Ok(plaintext) => {
                    console_log!("Decryption successful, {} bytes", plaintext.len());
                    let result = Uint8Array::from(&plaintext[..]);
                    Ok(JsValue::from(result))
                }
                Err(e) => {
                    console_error!("Decryption failed: {}", e);
                    Err(JsValue::from(e))
                }
            }
        };
        
        Ok(future_to_promise(future))
    }

    /// Get algorithm name
    #[wasm_bindgen(getter, js_name = algorithmName)]
    pub fn algorithm_name(&self) -> String {
        self.algorithm.name().to_string()
    }

    /// Get key size in bytes
    #[wasm_bindgen(getter, js_name = keySize)]
    pub fn key_size(&self) -> usize {
        self.algorithm.key_size()
    }

    /// Get nonce size in bytes
    #[wasm_bindgen(getter, js_name = nonceSize)]
    pub fn nonce_size(&self) -> usize {
        self.algorithm.nonce_size()
    }

    /// Get tag size in bytes
    #[wasm_bindgen(getter, js_name = tagSize)]
    pub fn tag_size(&self) -> usize {
        self.algorithm.tag_size()
    }

    /// Get algorithm information as object
    #[wasm_bindgen(js_name = getInfo)]
    pub fn get_info(&self) -> Result<Object, JsValue> {
        let info = AlgorithmInfo {
            name: self.algorithm.name().to_string(),
            key_size: self.algorithm.key_size(),
            nonce_size: self.algorithm.nonce_size(),
            tag_size: self.algorithm.tag_size(),
        };
        to_value(&info).map(|v| v.into())
    }
}

#[derive(serde::Serialize)]
struct AlgorithmInfo {
    name: String,
    key_size: usize,
    nonce_size: usize,
    tag_size: usize,
}

/// JavaScript wrapper for encryption profiles
#[wasm_bindgen]
pub struct EncryptionProfile {
    profile: fortress_core::encryption::EncryptionProfile,
}

#[wasm_bindgen]
impl EncryptionProfile {
    /// Create a new encryption profile
    #[wasm_bindgen(constructor)]
    pub fn new(algorithm_name: String, key_rotation_interval_secs: u64) -> Result<EncryptionProfile, JsValue> {
        console_log!("Creating encryption profile for algorithm: {}", algorithm_name);
        
        let algorithm = match algorithm_name.as_str() {
            "aegis256" => Box::new(Aegis256::new()) as Box<dyn EncryptionAlgorithm + Send + Sync>,
            "chacha20poly1305" => Box::new(ChaCha20Poly1305::new()),
            "aes256gcm" => Box::new(Aes256Gcm::new()),
            _ => {
                console_error!("Unknown algorithm: {}", algorithm_name);
                return Err(JsValue::from_str(&format!("Unknown algorithm: {}", algorithm_name)));
            }
        };

        let profile = fortress_core::encryption::EncryptionProfile::new(
            algorithm,
            std::time::Duration::from_secs(key_rotation_interval_secs),
        );

        Ok(EncryptionProfile { profile })
    }

    /// Get profile name
    #[wasm_bindgen(getter, js_name = name)]
    pub fn name(&self) -> String {
        self.profile.name().to_string()
    }

    /// Get algorithm name
    #[wasm_bindgen(getter, js_name = algorithm)]
    pub fn algorithm(&self) -> String {
        self.profile.algorithm().name().to_string()
    }

    /// Get key rotation interval in seconds
    #[wasm_bindgen(getter, js_name = keyRotationInterval)]
    pub fn key_rotation_interval(&self) -> u64 {
        self.profile.key_rotation_interval().as_secs()
    }

    /// Check if profile is secure
    #[wasm_bindgen(js_name = isSecure)]
    pub fn is_secure(&self) -> bool {
        self.profile.is_secure()
    }

    /// Get profile information as object
    #[wasm_bindgen(js_name = getInfo)]
    pub fn get_info(&self) -> Result<Object, JsValue> {
        let info = ProfileInfo {
            name: self.profile.name().to_string(),
            algorithm: self.profile.algorithm().name().to_string(),
            key_rotation_interval: self.profile.key_rotation_interval().as_secs(),
            is_secure: self.profile.is_secure(),
        };
        to_value(&info).map(|v| v.into())
    }
}

#[derive(serde::Serialize)]
struct ProfileInfo {
    name: String,
    algorithm: String,
    key_rotation_interval: u64,
    is_secure: bool,
}

/// Utility functions for encryption operations
#[wasm_bindgen]
pub fn generate_key(algorithm_name: String) -> Result<Uint8Array, JsValue> {
    console_log!("Generating key for algorithm: {}", algorithm_name);
    
    let algorithm = match algorithm_name.as_str() {
        "aegis256" => Box::new(Aegis256::new()) as Box<dyn EncryptionAlgorithm + Send + Sync>,
        "chacha20poly1305" => Box::new(ChaCha20Poly1305::new()),
        "aes256gcm" => Box::new(Aes256Gcm::new()),
        _ => {
            console_error!("Unknown algorithm: {}", algorithm_name);
            return Err(JsValue::from_str(&format!("Unknown algorithm: {}", algorithm_name)));
        }
    };

    let key_manager = KeyManager::new();
    match key_manager.generate_key(&*algorithm) {
        Ok(key) => {
            console_log!("Key generated successfully, {} bytes", key.len());
            Ok(Uint8Array::from(&key[..]))
        }
        Err(e) => {
            console_error!("Key generation failed: {}", e);
            Err(JsValue::from(e))
        }
    }
}

#[wasm_bindgen]
pub fn generate_nonce(algorithm_name: String) -> Result<Uint8Array, JsValue> {
    console_log!("Generating nonce for algorithm: {}", algorithm_name);
    
    let algorithm = match algorithm_name.as_str() {
        "aegis256" => Box::new(Aegis256::new()) as Box<dyn EncryptionAlgorithm + Send + Sync>,
        "chacha20poly1305" => Box::new(ChaCha20Poly1305::new()),
        "aes256gcm" => Box::new(Aes256Gcm::new()),
        _ => {
            console_error!("Unknown algorithm: {}", algorithm_name);
            return Err(JsValue::from_str(&format!("Unknown algorithm: {}", algorithm_name)));
        }
    };

    let nonce = vec![0u8; algorithm.nonce_size()];
    console_log!("Nonce generated successfully, {} bytes", nonce.len());
    Ok(Uint8Array::from(&nonce[..]))
}

/// Batch encryption utility
#[wasm_bindgen]
pub struct BatchEncryptor {
    algorithm: Box<dyn EncryptionAlgorithm + Send + Sync>,
}

#[wasm_bindgen]
impl BatchEncryptor {
    /// Create a new batch encryptor
    #[wasm_bindgen(constructor)]
    pub fn new(algorithm_name: String) -> Result<BatchEncryptor, JsValue> {
        console_log!("Creating batch encryptor for algorithm: {}", algorithm_name);
        
        let algorithm = match algorithm_name.as_str() {
            "aegis256" => Box::new(Aegis256::new()) as Box<dyn EncryptionAlgorithm + Send + Sync>,
            "chacha20poly1305" => Box::new(ChaCha20Poly1305::new()),
            "aes256gcm" => Box::new(Aes256Gcm::new()),
            _ => {
                console_error!("Unknown algorithm: {}", algorithm_name);
                return Err(JsValue::from_str(&format!("Unknown algorithm: {}", algorithm_name)));
            }
        };

        Ok(BatchEncryptor { algorithm })
    }

    /// Encrypt multiple data chunks with the same key
    #[wasm_bindgen(js_name = encryptBatch)]
    pub fn encrypt_batch(&self, chunks: js_sys::Array, key: &Uint8Array) -> Result<Promise, JsValue> {
        console_log!("Starting batch encryption of {} chunks", chunks.length());
        
        let mut plaintext_chunks = Vec::new();
        for i in 0..chunks.length() {
            let chunk = chunks.get(i).dyn_into::<Uint8Array>()
                .map_err(|e| JsValue::from_str(&format!("Invalid chunk at index {}: {:?}", i, e)))?;
            plaintext_chunks.push(chunk.to_vec());
        }
        
        let key_data = key.to_vec();
        let algorithm = self.algorithm.clone();
        
        let future = async move {
            let mut ciphertext_chunks = Vec::new();
            for (i, plaintext) in plaintext_chunks.iter().enumerate() {
                match algorithm.encrypt(plaintext, &key_data) {
                    Ok(ciphertext) => {
                        let result = Uint8Array::from(&ciphertext[..]);
                        ciphertext_chunks.push(result);
                    }
                    Err(e) => {
                        console_error!("Batch encryption failed at chunk {}: {}", i, e);
                        return Err(JsValue::from(e));
                    }
                }
            }
            
            console_log!("Batch encryption completed successfully");
            let result_array = js_sys::Array::new();
            for chunk in ciphertext_chunks {
                result_array.push(&chunk);
            }
            Ok(JsValue::from(result_array))
        };
        
        Ok(future_to_promise(future))
    }
}
