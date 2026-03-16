"""
Comprehensive tests for Fortress Python client
Tests all functionality including security, performance, and error handling
"""

import pytest
import time
import threading
from unittest.mock import Mock, patch

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'fortress'))

from fortress import (
    Fortress, 
    SecurityConfig, 
    PerformanceConfig,
    FortressError,
    FortressEncryptionError,
    FortressKeyError,
    FortressConfigError
)


class TestFortressClient:
    """Test suite for Fortress client functionality"""
    
    @pytest.fixture
    def security_config(self):
        """Create test security configuration"""
        return SecurityConfig(
            max_key_size=1024,
            max_data_size=1024 * 1024,  # 1MB
            rate_limit_requests=100,
            rate_limit_window=60,
            enable_audit_logging=False,  # Disable for tests
            require_key_id=False,
            allowed_algorithms=["aes256gcm", "chacha20poly1305"]
        )
    
    @pytest.fixture
    def performance_config(self):
        """Create test performance configuration"""
        return PerformanceConfig(
            connection_pool_size=2,
            connection_timeout=5.0,
            request_timeout=10.0,
            max_retries=2,
            retry_backoff=0.5,
            enable_caching=True,
            cache_size=100,
            cache_ttl=60
        )
    
    @pytest.fixture
    def fortress_client(self, security_config, performance_config):
        """Create Fortress client for testing"""
        client = Fortress(
            config={"profile": "test"},
            security_config=security_config,
            performance_config=performance_config
        )
        client.initialize()
        yield client
        client.shutdown()
    
    def test_client_initialization(self, security_config, performance_config):
        """Test client initialization with different configurations"""
        # Test successful initialization
        client = Fortress(
            config={"profile": "test"},
            security_config=security_config,
            performance_config=performance_config
        )
        assert client.initialize() is True
        assert client._initialized is True
        client.shutdown()
        
        # Test initialization with default configs
        client2 = Fortress()
        assert client2.initialize() is True
        assert client2._initialized is True
        client2.shutdown()
    
    def test_configuration_validation(self):
        """Test configuration validation"""
        # Test invalid security config
        with pytest.raises(FortressConfigError):
            bad_security = SecurityConfig(max_key_size=-1)
            Fortress(security_config=bad_security)
        
        # Test invalid performance config - check validation before creating client
        with pytest.raises(FortressConfigError):
            bad_performance = PerformanceConfig(connection_pool_size=0)  # 0 instead of -1
            Fortress(performance_config=bad_performance)
        
        # Test invalid algorithm in allowed list
        with pytest.raises(FortressConfigError):
            bad_security = SecurityConfig(allowed_algorithms=["invalid_algo"])
            Fortress(security_config=bad_security)
    
    def test_encryption_decryption(self, fortress_client):
        """Test encryption and decryption functionality"""
        test_data = b"Hello, Fortress! This is a test message."
        
        # Test encryption without key_id
        encrypted = fortress_client.encrypt(test_data)
        assert encrypted != test_data
        assert len(encrypted) > len(test_data)  # Should be larger due to salt/nonce
        
        # Test decryption
        decrypted = fortress_client.decrypt(encrypted, "test_key")
        assert decrypted == test_data
        
        # Test with specific algorithm
        encrypted_aes = fortress_client.encrypt(test_data, algorithm="aes256gcm")
        decrypted_aes = fortress_client.decrypt(encrypted_aes, "test_key", algorithm="aes256gcm")
        assert decrypted_aes == test_data
        
        # Test with ChaCha20-Poly1305
        encrypted_chacha = fortress_client.encrypt(test_data, algorithm="chacha20poly1305")
        decrypted_chacha = fortress_client.decrypt(encrypted_chacha, "test_key", algorithm="chacha20poly1305")
        assert decrypted_chacha == test_data
    
    def test_key_generation(self, fortress_client):
        """Test key generation functionality"""
        # Test key generation
        key_id = fortress_client.generate_key()
        assert isinstance(key_id, str)
        assert len(key_id) > 0
        
        # Test key generation with algorithm
        aes_key = fortress_client.generate_key(algorithm="aes256gcm")
        assert isinstance(aes_key, str)
        assert aes_key != key_id  # Should be different
        
        # Test key generation with metadata
        key_with_meta = fortress_client.generate_key(
            algorithm="chacha20poly1305",
            metadata={"purpose": "test", "owner": "unit_test"}
        )
        assert isinstance(key_with_meta, str)
        
        # Test key listing
        keys = fortress_client.list_keys()
        assert len(keys) >= 3  # At least the keys we generated
        assert key_id in keys
        assert aes_key in keys
        assert key_with_meta in keys
        
        # Test key info
        info = fortress_client.get_key_info(key_with_meta)
        assert info is not None
        assert "algorithm" in info
        assert "created_at" in info
        assert "metadata" in info
        assert info["algorithm"] == "chacha20poly1305"
        assert info["metadata"]["purpose"] == "test"
        
        # Test key deletion
        deleted = fortress_client.delete_key(key_id)
        assert deleted is True
        
        # Verify key is gone
        keys_after = fortress_client.list_keys()
        assert key_id not in keys_after
        
        # Test deleting non-existent key
        deleted_fake = fortress_client.delete_key("non_existent_key")
        assert deleted_fake is False
    
    def test_storage_operations(self, fortress_client):
        """Test storage backend operations"""
        test_key = "test_storage_key"
        test_data = b"This is test data for storage"
        
        # Test storing data
        stored = fortress_client.store_data(test_key, test_data)
        assert stored is True
        
        # Test retrieving data
        retrieved = fortress_client.retrieve_data(test_key)
        assert retrieved == test_data
        
        # Test retrieving non-existent data
        not_found = fortress_client.retrieve_data("non_existent_key")
        assert not_found is None
        
        # Test deleting data
        deleted = fortress_client.delete_data(test_key)
        assert deleted is True
        
        # Verify data is gone
        after_delete = fortress_client.retrieve_data(test_key)
        assert after_delete is None
        
        # Test deleting non-existent data
        delete_fake = fortress_client.delete_data("non_existent_key")
        assert delete_fake is False
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        # Create client with very restrictive rate limit
        security_config = SecurityConfig(rate_limit_requests=2, rate_limit_window=1)
        performance_config = PerformanceConfig()
        
        client = Fortress(
            security_config=security_config,
            performance_config=performance_config
        )
        client.initialize()
        
        try:
            # First two requests should succeed
            test_data = b"test"
            client.encrypt(test_data)  # First request
            client.encrypt(test_data)  # Second request
            
            # Third request should fail due to rate limit
            with pytest.raises(FortressError, match="Rate limit exceeded"):
                client.encrypt(test_data)
            
        finally:
            client.shutdown()
    
    def test_input_validation(self, fortress_client):
        """Test input validation for security"""
        # Test invalid data type
        with pytest.raises(FortressError, match="encrypt requires bytes input"):
            fortress_client.encrypt("not bytes")
        
        with pytest.raises(FortressError, match="decrypt requires bytes input"):
            fortress_client.decrypt("not bytes", "key")
        
        # Test oversized data
        large_data = b"x" * (1024 * 1024 + 1)  # Larger than max_data_size
        with pytest.raises(FortressError, match="encrypt data size exceeds maximum"):
            fortress_client.encrypt(large_data)
        
        # Test invalid algorithm
        with pytest.raises(FortressEncryptionError, match="Algorithm.*not allowed"):
            fortress_client.encrypt(b"test", algorithm="invalid_algo")
        
        # Test missing key_id for decryption
        with pytest.raises(FortressEncryptionError, match="key_id is required"):
            fortress_client.decrypt(b"test", "")
    
    def test_caching_functionality(self, fortress_client):
        """Test caching performance optimization"""
        test_data = b"Test data for caching"
        
        # First encryption should cache result
        encrypted1 = fortress_client.encrypt(test_data)
        
        # Second encryption with same inputs should use cache
        encrypted2 = fortress_client.encrypt(test_data)
        assert encrypted1 == encrypted2  # Should be identical due to caching
        
        # Test cache clearing
        fortress_client.clear_cache()
        
        # After clearing cache, should still work but might be different
        encrypted3 = fortress_client.encrypt(test_data)
        # Note: Due to random salts, encrypted data will be different even with same input
        
        # Test performance metrics
        metrics = fortress_client.get_performance_metrics()
        assert "cache_size" in metrics
        assert "rust_backend_available" in metrics
        assert "initialized" in metrics
        assert metrics["initialized"] is True
    
    def test_context_manager(self):
        """Test context manager functionality"""
        security_config = SecurityConfig(enable_audit_logging=False)
        performance_config = PerformanceConfig()
        
        with Fortress(security_config=security_config, 
                     performance_config=performance_config) as client:
            assert client._initialized is True
            
            # Should be able to use client normally
            encrypted = client.encrypt(b"test")
            decrypted = client.decrypt(encrypted, "test_key")
            assert decrypted == b"test"
        
        # Client should be shut down after context
        assert client._initialized is False
    
    def test_error_handling(self, fortress_client):
        """Test comprehensive error handling"""
        # Test operations on uninitialized client
        uninitialized = Fortress()
        with pytest.raises(RuntimeError, match="Fortress not initialized"):
            uninitialized.encrypt(b"test")
        
        # Test invalid ciphertext format
        with pytest.raises(FortressEncryptionError, match="Invalid ciphertext format"):
            fortress_client.decrypt(b"too_short", "test_key")
        
        # Test algorithm validation
        with pytest.raises(FortressEncryptionError, match="Algorithm invalid_algo not allowed"):
            # Temporarily modify config to test this
            original_allowed = fortress_client.security_config.allowed_algorithms
            fortress_client.security_config.allowed_algorithms = ["aes256gcm"]
            try:
                fortress_client.encrypt(b"test", algorithm="invalid_algo")
            finally:
                fortress_client.security_config.allowed_algorithms = original_allowed
    
    def test_concurrent_access(self, fortress_client):
        """Test thread safety and concurrent access"""
        results = []
        errors = []
        
        def worker(worker_id):
            try:
                # Each thread performs operations
                for i in range(5):
                    data = f"Worker {worker_id} - Iteration {i}".encode()
                    encrypted = fortress_client.encrypt(data)
                    decrypted = fortress_client.decrypt(encrypted, f"key_{worker_id}")
                    assert decrypted == data
                    results.append(worker_id)
            except Exception as e:
                errors.append((worker_id, str(e)))
        
        # Create multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify results
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == 25  # 5 threads * 5 iterations each
    
    def test_algorithm_list(self, fortress_client):
        """Test algorithm listing functionality"""
        algorithms = fortress_client.list_algorithms()
        assert isinstance(algorithms, list)
        assert len(algorithms) > 0
        assert "aes256gcm" in algorithms
        assert "chacha20poly1305" in algorithms
    
    def test_version_info(self, fortress_client):
        """Test version information"""
        version = fortress_client.get_version()
        assert isinstance(version, str)
        assert len(version) > 0
    
    def test_performance_metrics(self, fortress_client):
        """Test performance metrics collection"""
        # Perform some operations to generate metrics
        fortress_client.encrypt(b"test")
        fortress_client.store_data("test_key", b"test_data")
        
        metrics = fortress_client.get_performance_metrics()
        assert isinstance(metrics, dict)
        
        required_keys = [
            "cache_size", "cache_hit_ratio", "connection_pool_size",
            "active_connections", "rate_limit_remaining", 
            "rust_backend_available", "initialized"
        ]
        
        for key in required_keys:
            assert key in metrics
        
        assert metrics["initialized"] is True
        assert isinstance(metrics["cache_size"], int)
        assert isinstance(metrics["cache_hit_ratio"], float)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
