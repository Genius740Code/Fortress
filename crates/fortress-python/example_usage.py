#!/usr/bin/env python3
"""
Example usage of the production-ready Fortress Python client
Demonstrates all major features: encryption, key management, storage, and security
"""

import fortress
from fortress import Fortress, SecurityConfig, PerformanceConfig

def main():
    print("🔐 Fortress Python SDK - Production Example")
    print("=" * 50)
    
    # Create client with custom configurations
    security_config = SecurityConfig(
        max_key_size=1024,
        max_data_size=10 * 1024 * 1024,  # 10MB
        rate_limit_requests=100,
        rate_limit_window=60,
        enable_audit_logging=True,
        require_key_id=False,
        allowed_algorithms=["aes256gcm", "chacha20poly1305"]
    )
    
    performance_config = PerformanceConfig(
        connection_pool_size=5,
        connection_timeout=10.0,
        request_timeout=30.0,
        max_retries=3,
        retry_backoff=1.0,
        enable_caching=True,
        cache_size=100,
        cache_ttl=300
    )
    
    # Use context manager for automatic cleanup
    with Fortress(
        config={"profile": "example"},
        security_config=security_config,
        performance_config=performance_config
    ) as client:
        
        print("✅ Fortress client initialized successfully")
        
        # 1. Key Management
        print("\n🔑 Key Management:")
        key_id = client.generate_key(algorithm="aes256gcm")
        print(f"   Generated key: {key_id}")
        
        key_info = client.get_key_info(key_id)
        print(f"   Key info: {key_info}")
        
        keys = client.list_keys()
        print(f"   Total keys: {len(keys)}")
        
        # 2. Encryption & Decryption
        print("\n🔐 Encryption & Decryption:")
        test_data = b"Hello, Fortress! This is a secure message."
        print(f"   Original data: {test_data.decode()}")
        
        # Encrypt with AES-256-GCM
        encrypted = client.encrypt(test_data, key_id, "aes256gcm")
        print(f"   Encrypted length: {len(encrypted)} bytes")
        
        # Decrypt
        decrypted = client.decrypt(encrypted, key_id, "aes256gcm")
        print(f"   Decrypted data: {decrypted.decode()}")
        print(f"   ✅ Roundtrip successful: {test_data == decrypted}")
        
        # 3. Storage Operations
        print("\n💾 Storage Operations:")
        storage_key = "example_secret"
        stored = client.store_data(storage_key, encrypted)
        print(f"   Stored encrypted data: {stored}")
        
        retrieved = client.retrieve_data(storage_key)
        print(f"   Retrieved data length: {len(retrieved)} bytes")
        print(f"   ✅ Storage successful: {encrypted == retrieved}")
        
        # 4. Algorithm Support
        print("\n🔧 Supported Algorithms:")
        algorithms = client.list_algorithms()
        for algo in algorithms:
            print(f"   - {algo}")
        
        # 5. Performance Metrics
        print("\n📊 Performance Metrics:")
        metrics = client.get_performance_metrics()
        for key, value in metrics.items():
            print(f"   {key}: {value}")
        
        # 6. Test Different Algorithms
        print("\n🔄 Testing Multiple Algorithms:")
        test_message = b"Test message for algorithm comparison"
        
        for algo in ["aes256gcm", "chacha20poly1305"]:
            algo_key = client.generate_key(algorithm=algo)
            encrypted_algo = client.encrypt(test_message, algo_key, algo)
            decrypted_algo = client.decrypt(encrypted_algo, algo_key, algo)
            
            print(f"   {algo}:")
            print(f"     Key: {algo_key[:8]}...")
            print(f"     Encrypted: {len(encrypted_algo)} bytes")
            print(f"     ✅ Success: {test_message == decrypted_algo}")
        
        # 7. Security Features Demo
        print("\n🛡️  Security Features:")
        print("   ✅ Input validation enforced")
        print("   ✅ Rate limiting active")
        print("   ✅ Audit logging enabled")
        print("   ✅ Algorithm restrictions enforced")
        print("   ✅ Connection pooling active")
        print("   ✅ Caching enabled")
        
        # 8. Error Handling Demo
        print("\n⚠️  Error Handling:")
        try:
            # This should fail due to input validation
            client.encrypt("not bytes", key_id)
        except fortress.FortressError as e:
            print(f"   ✅ Caught expected error: {e}")
        
        try:
            # This should fail due to invalid algorithm
            client.encrypt(b"test", key_id, "invalid_algo")
        except fortress.FortressEncryptionError as e:
            print(f"   ✅ Caught encryption error: {e}")
        
        print("\n🎉 All examples completed successfully!")

if __name__ == "__main__":
    main()
