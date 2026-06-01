//! Comprehensive tests for zero-knowledge proof features

use super::*;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Test suite for Schnorr proofs
#[cfg(test)]
mod schnorr_proof_tests {
    use super::*;

    #[test]
    fn test_schnorr_basic_proof() {
        let statement = b"test_statement_123".to_vec();
        let witness = SecureKey::new(vec![1, 2, 3, 4, 5]);

        // Generate proof
        let proof = SchnorrProof::prove(&statement, &witness).unwrap();

        // Verify with correct statement
        let verified = SchnorrProof::verify(&statement, &proof).unwrap();
        assert!(verified);

        // Verify with wrong statement
        let wrong_statement = b"wrong_statement_456".to_vec();
        let not_verified = SchnorrProof::verify(&wrong_statement, &proof).unwrap();
        assert!(!not_verified);
    }

    #[test]
    fn test_schnorr_different_witnesses() {
        let statement = b"constant_statement".to_vec();
        let witness1 = SecureKey::new(vec![1, 2, 3, 4, 5]);
        let witness2 = SecureKey::new(vec![5, 4, 3, 2, 1]);

        let proof1 = SchnorrProof::prove(&statement, &witness1).unwrap();
        let proof2 = SchnorrProof::prove(&statement, &witness2).unwrap();

        // Both proofs should verify with the same statement
        assert!(SchnorrProof::verify(&statement, &proof1).unwrap());
        assert!(SchnorrProof::verify(&statement, &proof2).unwrap());

        // But proofs should be different
        assert_ne!(proof1.commitment, proof2.commitment);
        assert_ne!(proof1.response, proof2.response);
    }

    #[test]
    fn test_schnorr_large_data() {
        let statement = vec![42u8; 10000];
        let witness = SecureKey::generate_random(64).unwrap();

        let proof = SchnorrProof::prove(&statement, &witness).unwrap();
        let verified = SchnorrProof::verify(&statement, &proof).unwrap();

        assert!(verified);
    }

    #[test]
    fn test_schnorr_security_level() {
        let level = SchnorrProof::security_level();
        assert_eq!(level.bits(), 128);
        assert_eq!(level.recommended_curve(), "BLS12-381");
    }
}

/// Test suite for Access Control proofs
#[cfg(test)]
mod access_control_tests {
    use super::*;

    #[test]
    fn test_access_control_proof_creation() {
        let user_key = SecureKey::generate_random(32).unwrap();
        let resource_policy = b"admin_access_required".to_vec();
        let permissions = b"read,write,admin".to_vec();

        let proof =
            AccessControlProof::create_proof(&user_key, &resource_policy, &permissions).unwrap();

        // Verify basic structure
        assert!(!proof.user_id_hash.is_empty());
        assert!(!proof.resource_id_hash.is_empty());
        assert!(!proof.permissions_hash.is_empty());
        assert!(!proof.proof.is_empty());
        assert!(proof.timestamp <= Utc::now());
    }

    #[test]
    fn test_access_control_proof_verification() {
        let user_key = SecureKey::generate_random(32).unwrap();
        let resource_policy = b"admin_access_required".to_vec();
        let permissions = b"read,write,admin".to_vec();

        let proof =
            AccessControlProof::create_proof(&user_key, &resource_policy, &permissions).unwrap();

        // Verify with correct policy
        let verified = proof.verify_proof(&resource_policy).unwrap();
        assert!(verified);

        // Verify with wrong policy
        let wrong_policy = b"read_only_required".to_vec();
        let not_verified = proof.verify_proof(&wrong_policy).unwrap();
        assert!(!not_verified);
    }

    #[test]
    fn test_access_control_proof_expiration() {
        let user_key = SecureKey::generate_random(32).unwrap();
        let resource_policy = b"test_policy".to_vec();
        let permissions = b"read".to_vec();

        let proof =
            AccessControlProof::create_proof(&user_key, &resource_policy, &permissions).unwrap();

        // Should be valid for reasonable time
        assert!(proof.is_valid(3600)); // 1 hour
        assert!(proof.is_valid(86400)); // 24 hours

        // Should not be valid for very short times
        assert!(!proof.is_valid(0)); // 0 seconds
    }

    #[test]
    fn test_access_control_different_permissions() {
        let user_key = SecureKey::generate_random(32).unwrap();
        let resource_policy = b"test_policy".to_vec();

        let permissions1 = b"read,write,admin".to_vec();
        let permissions2 = b"read,write".to_vec();
        let permissions3 = b"read".to_vec();

        let proof1 =
            AccessControlProof::create_proof(&user_key, &resource_policy, &permissions1).unwrap();
        let proof2 =
            AccessControlProof::create_proof(&user_key, &resource_policy, &permissions2).unwrap();
        let proof3 =
            AccessControlProof::create_proof(&user_key, &resource_policy, &permissions3).unwrap();

        // All should verify with same policy
        assert!(proof1.verify_proof(&resource_policy).unwrap());
        assert!(proof2.verify_proof(&resource_policy).unwrap());
        assert!(proof3.verify_proof(&resource_policy).unwrap());

        // But permission hashes should be different
        assert_ne!(proof1.permissions_hash, proof2.permissions_hash);
        assert_ne!(proof2.permissions_hash, proof3.permissions_hash);
        assert_ne!(proof1.permissions_hash, proof3.permissions_hash);
    }

    #[test]
    fn test_access_control_circuit() {
        let policy = b"test_policy";
        let permissions = b"read,write";

        let circuit = AccessControlCircuit::build(policy, permissions).unwrap();
        assert!(!circuit.constraints.is_empty());
        assert_eq!(circuit.public_inputs.len(), 1);
        assert_eq!(circuit.private_inputs.len(), 1);

        let user_key = SecureKey::generate_random(32).unwrap();
        let witness = circuit.create_witness(&user_key).unwrap();
        assert!(!witness.is_empty());
    }
}

/// Test suite for Anonymous Authentication
#[cfg(test)]
mod anonymous_auth_tests {
    use super::*;

    #[test]
    fn test_anonymous_auth_user_registration() {
        let mut auth = AnonymousAuth::new(SecurityLevel::Level128);

        let user_id = UserId::from_string("test_user");
        let credential = auth.register_user(user_id.clone(), 30).unwrap();

        // Verify credential structure
        assert!(!credential.public_key.is_empty());
        assert_eq!(credential.secret_key.len(), 32);
        assert!(credential.issued_at <= Utc::now());
        assert!(credential.expires_at > credential.issued_at);

        // Verify credential is stored
        assert!(auth.user_credentials.contains_key(&user_id));
    }

    #[test]
    fn test_anonymous_auth_authentication() {
        let mut auth = AnonymousAuth::new(SecurityLevel::Level192);

        let user_id = UserId::from_string("test_user");
        auth.register_user(user_id.clone(), 30).unwrap();

        let challenge = b"authentication_challenge";
        let proof = auth.authenticate_anonymously(&user_id, challenge).unwrap();

        // Verify proof structure
        assert!(!proof.proof.is_empty());
        assert!(proof.timestamp <= Utc::now());
        assert!(!proof.challenge_hash.is_empty());

        // Verify proof
        let verified = auth.verify_anonymous(&proof, challenge).unwrap();
        assert!(verified);

        // Verify with wrong challenge fails
        let wrong_challenge = b"wrong_challenge";
        let not_verified = auth.verify_anonymous(&proof, wrong_challenge).unwrap();
        assert!(!not_verified);
    }

    #[test]
    fn test_anonymous_auth_multiple_users() {
        let mut auth = AnonymousAuth::new(SecurityLevel::Level256);

        let user1 = UserId::from_string("user1");
        let user2 = UserId::from_string("user2");
        let user3 = UserId::from_string("user3");

        auth.register_user(user1.clone(), 30).unwrap();
        auth.register_user(user2.clone(), 30).unwrap();
        auth.register_user(user3.clone(), 30).unwrap();

        let challenge = b"challenge";

        let proof1 = auth.authenticate_anonymously(&user1, challenge).unwrap();
        let proof2 = auth.authenticate_anonymously(&user2, challenge).unwrap();
        let proof3 = auth.authenticate_anonymously(&user3, challenge).unwrap();

        // All proofs should verify
        assert!(auth.verify_anonymous(&proof1, challenge).unwrap());
        assert!(auth.verify_anonymous(&proof2, challenge).unwrap());
        assert!(auth.verify_anonymous(&proof3, challenge).unwrap());

        // But proofs should be different
        assert_ne!(proof1.proof, proof2.proof);
        assert_ne!(proof2.proof, proof3.proof);
        assert_ne!(proof1.proof, proof3.proof);

        // And proof IDs should be unique
        assert_ne!(proof1.proof_id, proof2.proof_id);
        assert_ne!(proof2.proof_id, proof3.proof_id);
        assert_ne!(proof1.proof_id, proof3.proof_id);
    }

    #[test]
    fn test_anonymous_auth_nonexistent_user() {
        let auth = AnonymousAuth::new(SecurityLevel::Level128);

        let user_id = UserId::from_string("nonexistent_user");
        let challenge = b"challenge";

        // Should fail for nonexistent user
        let result = auth.authenticate_anonymously(&user_id, challenge);
        assert!(result.is_err());
    }

    #[test]
    fn test_group_parameters() {
        let auth = AnonymousAuth::new(SecurityLevel::Level256);

        let params = &auth.group_params;
        assert!(!params.generator.is_empty());
        assert!(!params.order.is_empty());
        assert_eq!(params.security_level, SecurityLevel::Level256);
    }

    #[test]
    fn test_user_id_creation() {
        let id1 = UserId::from_string("test_user");
        let id2 = UserId::from_string("test_user");
        let id3 = UserId::from_string("different_user");

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);

        // Test bytes access
        assert!(!id1.as_bytes().is_empty());
        assert_eq!(id1.as_bytes().len(), 32); // SHA256 output
    }
}

/// Test suite for GDPR Compliance proofs
#[cfg(test)]
mod gdpr_compliance_tests {
    use super::*;

    #[test]
    fn test_gdpr_compliance_proof_creation() {
        let data_subject = PersonalData {
            id: vec![1, 2, 3, 4],
            created_at: Utc::now(),
            category: "personal".to_string(),
            processing_purposes: vec!["marketing".to_string()],
        };

        let processing_purpose = ProcessingPurpose {
            id: vec![5, 6, 7, 8],
            description: "Direct marketing".to_string(),
            legal_basis: "Consent".to_string(),
        };

        let consent_record = ConsentRecord {
            id: vec![9, 10, 11, 12],
            timestamp: Utc::now(),
            granted: true,
            scope: vec!["marketing".to_string()],
        };

        let proof = GdprComplianceProof::create_compliance_proof(
            &data_subject,
            &processing_purpose,
            &consent_record,
            365,
        )
        .unwrap();

        // Verify proof structure
        assert!(!proof.data_subject_hash.is_empty());
        assert!(!proof.processing_purpose_hash.is_empty());
        assert!(!proof.consent_proof.is_empty());
        assert!(!proof.retention_compliance_proof.is_empty());
        assert!(!proof.data_subject_rights_proof.is_empty());
        assert!(proof.timestamp <= Utc::now());
        assert!(proof.valid_until > proof.timestamp);
    }

    #[test]
    fn test_gdpr_compliance_verification() {
        let data_subject = PersonalData {
            id: vec![1, 2, 3, 4],
            created_at: Utc::now(),
            category: "personal".to_string(),
            processing_purposes: vec!["analytics".to_string()],
        };

        let processing_purpose = ProcessingPurpose {
            id: vec![5, 6, 7, 8],
            description: "Analytics".to_string(),
            legal_basis: "Legitimate Interest".to_string(),
        };

        let consent_record = ConsentRecord {
            id: vec![9, 10, 11, 12],
            timestamp: Utc::now(),
            granted: true,
            scope: vec!["analytics".to_string()],
        };

        let proof = GdprComplianceProof::create_compliance_proof(
            &data_subject,
            &processing_purpose,
            &consent_record,
            180,
        )
        .unwrap();

        // Should verify
        let verified = proof.verify_compliance().unwrap();
        assert!(verified);
    }

    #[test]
    fn test_gdpr_compliance_expiration() {
        let data_subject = PersonalData {
            id: vec![1, 2, 3, 4],
            created_at: Utc::now(),
            category: "sensitive".to_string(),
            processing_purposes: vec!["health".to_string()],
        };

        let processing_purpose = ProcessingPurpose {
            id: vec![5, 6, 7, 8],
            description: "Healthcare".to_string(),
            legal_basis: "Explicit Consent".to_string(),
        };

        let consent_record = ConsentRecord {
            id: vec![9, 10, 11, 12],
            timestamp: Utc::now(),
            granted: true,
            scope: vec!["health".to_string()],
        };

        let proof = GdprComplianceProof::create_compliance_proof(
            &data_subject,
            &processing_purpose,
            &consent_record,
            365,
        )
        .unwrap();

        // Should be valid (created recently)
        assert!(proof.verify_compliance().unwrap());

        // Mock expired proof by modifying timestamp
        let mut expired_proof = proof.clone();
        expired_proof.valid_until = Utc::now() - chrono::Duration::days(1);

        // Should not verify expired
        assert!(!expired_proof.verify_compliance().unwrap());
    }

    #[test]
    fn test_gdpr_different_consent() {
        let data_subject = PersonalData {
            id: vec![1, 2, 3, 4],
            created_at: Utc::now(),
            category: "personal".to_string(),
            processing_purposes: vec!["marketing".to_string()],
        };

        let processing_purpose = ProcessingPurpose {
            id: vec![5, 6, 7, 8],
            description: "Marketing".to_string(),
            legal_basis: "Consent".to_string(),
        };

        let consent_granted = ConsentRecord {
            id: vec![9, 10, 11, 12],
            timestamp: Utc::now(),
            granted: true,
            scope: vec!["marketing".to_string()],
        };

        let consent_denied = ConsentRecord {
            id: vec![13, 14, 15, 16],
            timestamp: Utc::now(),
            granted: false,
            scope: vec!["marketing".to_string()],
        };

        let proof_granted = GdprComplianceProof::create_compliance_proof(
            &data_subject,
            &processing_purpose,
            &consent_granted,
            365,
        )
        .unwrap();

        let proof_denied = GdprComplianceProof::create_compliance_proof(
            &data_subject,
            &processing_purpose,
            &consent_denied,
            365,
        )
        .unwrap();

        // Both should verify (as proofs of compliance state)
        assert!(proof_granted.verify_compliance().unwrap());
        assert!(proof_denied.verify_compliance().unwrap());

        // But consent proofs should be different
        assert_ne!(proof_granted.consent_proof, proof_denied.consent_proof);
    }
}

/// Test suite for Security Levels
#[cfg(test)]
mod security_level_tests {
    use super::*;

    #[test]
    fn test_security_level_properties() {
        assert_eq!(SecurityLevel::Level128.bits(), 128);
        assert_eq!(SecurityLevel::Level192.bits(), 192);
        assert_eq!(SecurityLevel::Level256.bits(), 256);

        assert_eq!(SecurityLevel::Level128.recommended_curve(), "BLS12-381");
        assert_eq!(SecurityLevel::Level192.recommended_curve(), "BLS12-381");
        assert_eq!(SecurityLevel::Level256.recommended_curve(), "BLS12-381");
    }

    #[test]
    fn test_security_level_serialization() {
        let level = SecurityLevel::Level256;

        // Test serialization
        let serialized = serde_json::to_string(&level).unwrap();
        let deserialized: SecurityLevel = serde_json::from_str(&serialized).unwrap();

        assert_eq!(level, deserialized);
    }
}

/// Performance benchmarks for zero-knowledge proofs
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn benchmark_schnorr_proof_generation() {
        let statement = b"benchmark_statement";
        let witness = SecureKey::generate_random(32).unwrap();
        let iterations = 1000;

        let start = Instant::now();
        let mut proofs = Vec::new();
        for _ in 0..iterations {
            let statement_vec = statement.to_vec();
            proofs.push(SchnorrProof::prove(&statement_vec, &witness).unwrap());
        }
        let generation_duration = start.elapsed();

        let start = Instant::now();
        for proof in &proofs {
            let statement_vec = statement.to_vec();
            SchnorrProof::verify(&statement_vec, proof).unwrap();
        }
        let verification_duration = start.elapsed();

        println!(
            "Schnorr proof generation ({} iterations): {:?}",
            iterations, generation_duration
        );
        println!(
            "Schnorr proof verification ({} iterations): {:?}",
            iterations, verification_duration
        );

        // Should be reasonably fast
        assert!(generation_duration.as_millis() < 5000);
        assert!(verification_duration.as_millis() < 2000);
    }

    #[test]
    fn benchmark_access_control_proofs() {
        let user_key = SecureKey::generate_random(32).unwrap();
        let resource_policy = b"benchmark_policy";
        let permissions = b"read,write,admin";
        let iterations = 500;

        let start = Instant::now();
        let mut proofs = Vec::new();
        for _ in 0..iterations {
            proofs.push(
                AccessControlProof::create_proof(&user_key, resource_policy, permissions).unwrap(),
            );
        }
        let generation_duration = start.elapsed();

        let start = Instant::now();
        for proof in &proofs {
            proof.verify_proof(resource_policy).unwrap();
        }
        let verification_duration = start.elapsed();

        println!(
            "Access control proof generation ({} iterations): {:?}",
            iterations, generation_duration
        );
        println!(
            "Access control proof verification ({} iterations): {:?}",
            iterations, verification_duration
        );

        // Should be reasonably fast
        assert!(generation_duration.as_millis() < 10000);
        assert!(verification_duration.as_millis() < 5000);
    }

    #[test]
    fn benchmark_anonymous_authentication() {
        let mut auth = AnonymousAuth::new(SecurityLevel::Level128);
        let user_id = UserId::from_string("benchmark_user");
        auth.register_user(user_id.clone(), 30).unwrap();

        let challenge = b"benchmark_challenge";
        let iterations = 500;

        let start = Instant::now();
        let mut proofs = Vec::new();
        for _ in 0..iterations {
            proofs.push(auth.authenticate_anonymously(&user_id, challenge).unwrap());
        }
        let generation_duration = start.elapsed();

        let start = Instant::now();
        for proof in &proofs {
            auth.verify_anonymous(proof, challenge).unwrap();
        }
        let verification_duration = start.elapsed();

        println!(
            "Anonymous auth proof generation ({} iterations): {:?}",
            iterations, generation_duration
        );
        println!(
            "Anonymous auth proof verification ({} iterations): {:?}",
            iterations, verification_duration
        );

        // Should be reasonably fast
        assert!(generation_duration.as_millis() < 10000);
        assert!(verification_duration.as_millis() < 5000);
    }
}

/// Integration tests combining multiple ZK features
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_multi_proof_workflow() {
        // Generate user key
        let user_key = SecureKey::generate_random(32).unwrap();

        // Create access control proof
        let resource_policy = b"admin_access";
        let permissions = b"read,write,admin";
        let access_proof =
            AccessControlProof::create_proof(&user_key, resource_policy, permissions).unwrap();

        // Create anonymous authentication
        let mut auth = AnonymousAuth::new(SecurityLevel::Level256);
        let user_id = UserId::from_string("integration_user");
        auth.register_user(user_id.clone(), 30).unwrap();

        let challenge = b"integration_challenge";
        let anon_proof = auth.authenticate_anonymously(&user_id, challenge).unwrap();

        // Create Schnorr proof
        let statement = b"integration_statement";
        let statement_vec = statement.to_vec();
        let schnorr_proof = SchnorrProof::prove(&statement_vec, &user_key).unwrap();

        // Verify all proofs
        assert!(access_proof.verify_proof(resource_policy).unwrap());
        assert!(auth.verify_anonymous(&anon_proof, challenge).unwrap());
        assert!(SchnorrProof::verify(&statement_vec, &schnorr_proof).unwrap());

        // All proofs should be different
        assert_ne!(access_proof.proof_id, anon_proof.proof_id);
        assert!(schnorr_proof.commitment != access_proof.user_id_hash);
    }

    #[test]
    fn test_concurrent_proof_generation() {
        let user_key = Arc::new(SecureKey::generate_random(32).unwrap());
        let mut handles = Vec::new();

        // Spawn threads generating different types of proofs
        for i in 0..10 {
            let key_clone = Arc::clone(&user_key);
            let handle = thread::spawn(move || {
                let resource_policy = format!("policy_{}", i);
                let permissions = format!("permissions_{}", i);

                // Generate access control proof
                let access_proof = AccessControlProof::create_proof(
                    &key_clone,
                    resource_policy.as_bytes(),
                    permissions.as_bytes(),
                )
                .unwrap();

                // Generate Schnorr proof
                let statement = format!("statement_{}", i);
                let statement_vec = statement.as_bytes().to_vec();
                let schnorr_proof = SchnorrProof::prove(&statement_vec, &key_clone).unwrap();

                (access_proof.proof_id, schnorr_proof.commitment)
            });
            handles.push(handle);
        }

        // Collect results
        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.join().unwrap());
        }

        // Verify all results are unique
        for (i, (access_id, schnorr_commit)) in results.iter().enumerate() {
            for (j, (other_access_id, other_schnorr_commit)) in results.iter().enumerate() {
                if i != j {
                    assert_ne!(access_id, other_access_id);
                    assert_ne!(schnorr_commit, other_schnorr_commit);
                }
            }
        }
    }

    #[test]
    fn test_gdpr_with_anonymous_auth() {
        // Set up GDPR compliance
        let data_subject = PersonalData {
            id: vec![1, 2, 3, 4],
            created_at: Utc::now(),
            category: "health".to_string(),
            processing_purposes: vec!["treatment".to_string()],
        };

        let processing_purpose = ProcessingPurpose {
            id: vec![5, 6, 7, 8],
            description: "Medical Treatment".to_string(),
            legal_basis: "Explicit Consent".to_string(),
        };

        let consent_record = ConsentRecord {
            id: vec![9, 10, 11, 12],
            timestamp: Utc::now(),
            granted: true,
            scope: vec!["treatment".to_string()],
        };

        let gdpr_proof = GdprComplianceProof::create_compliance_proof(
            &data_subject,
            &processing_purpose,
            &consent_record,
            730, // 2 years
        )
        .unwrap();

        // Set up anonymous authentication
        let mut auth = AnonymousAuth::new(SecurityLevel::Level192);
        let user_id = UserId::from_string("patient_user");
        auth.register_user(user_id.clone(), 30).unwrap();

        let challenge = b"medical_access_challenge";
        let anon_proof = auth.authenticate_anonymously(&user_id, challenge).unwrap();

        // Verify both proofs
        assert!(gdpr_proof.verify_compliance().unwrap());
        assert!(auth.verify_anonymous(&anon_proof, challenge).unwrap());

        // Proofs should be independent
        assert_ne!(gdpr_proof.timestamp, anon_proof.timestamp);
    }

    #[test]
    fn test_security_level_consistency() {
        // Test that all proof systems respect security levels
        let schnorr_level = SchnorrProof::security_level();
        let auth = AnonymousAuth::new(schnorr_level.clone());

        assert_eq!(schnorr_level, auth.group_params.security_level);

        // Test different security levels
        for level in [
            SecurityLevel::Level128,
            SecurityLevel::Level192,
            SecurityLevel::Level256,
        ] {
            let auth = AnonymousAuth::new(level.clone());
            assert_eq!(auth.group_params.security_level, level);
            assert_eq!(auth.group_params.security_level.bits(), level.bits());
        }
    }
}

/// Error handling tests
#[cfg(test)]
mod error_tests {
    use super::*;

    #[test]
    fn test_schnorr_invalid_inputs() {
        let statement = b"test";
        let witness = SecureKey::new(vec![]);

        // Should still work with empty witness
        let statement_vec = statement.to_vec();
        let proof = SchnorrProof::prove(&statement_vec, &witness).unwrap();
        assert!(SchnorrProof::verify(&statement_vec, &proof).unwrap());
    }

    #[test]
    fn test_access_control_empty_inputs() {
        let user_key = SecureKey::new(vec![]);
        let resource_policy = b"";
        let permissions = b"".to_vec();

        let proof =
            AccessControlProof::create_proof(&user_key, resource_policy, &permissions).unwrap();
        assert!(proof.verify_proof(resource_policy).unwrap());
    }

    #[test]
    fn test_anonymous_auth_invalid_user() {
        let auth = AnonymousAuth::new(SecurityLevel::Level128);
        let user_id = UserId::from_string("nonexistent");
        let challenge = b"challenge";

        let result = auth.authenticate_anonymously(&user_id, challenge);
        assert!(result.is_err());
    }

    #[test]
    fn test_gdpr_empty_records() {
        let data_subject = PersonalData {
            id: vec![],
            created_at: Utc::now(),
            category: "".to_string(),
            processing_purposes: vec![],
        };

        let processing_purpose = ProcessingPurpose {
            id: vec![],
            description: "".to_string(),
            legal_basis: "".to_string(),
        };

        let consent_record = ConsentRecord {
            id: vec![],
            timestamp: Utc::now(),
            granted: false,
            scope: vec![],
        };

        let proof = GdprComplianceProof::create_compliance_proof(
            &data_subject,
            &processing_purpose,
            &consent_record,
            0,
        )
        .unwrap();

        assert!(proof.verify_compliance().unwrap());
    }
}
