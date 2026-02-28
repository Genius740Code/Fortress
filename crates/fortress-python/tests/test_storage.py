#!/usr/bin/env python3
"""
Test suite for Fortress Python SDK storage functionality
"""

import pytest
import asyncio
import tempfile
import os
import fortress
from typing import Dict, Any, List


class TestStorageBackend:
    """Test storage backend operations"""
    
    @pytest.fixture
    async def local_storage(self):
        """Create a local storage backend for testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = fortress.create_local_config(temp_dir)
            backend = fortress.StorageBackend(config)
            yield backend
    
    @pytest.fixture
    def sample_data(self) -> bytes:
        """Sample data for storage tests"""
        return b"Hello, Fortress! This is test data for storage."
    
    @pytest.mark.asyncio
    async def test_store_and_retrieve(self, local_storage, sample_data):
        """Test storing and retrieving data"""
        key = "test_key"
        
        # Store data
        await local_storage.store(key, sample_data)
        
        # Retrieve data
        retrieved_data = await local_storage.retrieve(key)
        assert retrieved_data == sample_data
    
    @pytest.mark.asyncio
    async def test_store_overwrite(self, local_storage, sample_data):
        """Test overwriting existing data"""
        key = "test_key"
        original_data = b"Original data"
        new_data = b"New data"
        
        # Store original data
        await local_storage.store(key, original_data)
        
        # Overwrite with new data
        await local_storage.store(key, new_data)
        
        # Retrieve and verify
        retrieved_data = await local_storage.retrieve(key)
        assert retrieved_data == new_data
    
    @pytest.mark.asyncio
    async def test_retrieve_nonexistent_key_fails(self, local_storage):
        """Test that retrieving nonexistent key fails"""
        with pytest.raises(fortress.FortressError):
            await local_storage.retrieve("nonexistent_key")
    
    @pytest.mark.asyncio
    async def test_delete_key(self, local_storage, sample_data):
        """Test deleting a key"""
        key = "test_key"
        
        # Store data
        await local_storage.store(key, sample_data)
        
        # Verify it exists
        retrieved_data = await local_storage.retrieve(key)
        assert retrieved_data == sample_data
        
        # Delete key
        await local_storage.delete(key)
        
        # Verify it's deleted
        with pytest.raises(fortress.FortressError):
            await local_storage.retrieve(key)
    
    @pytest.mark.asyncio
    async def test_delete_nonexistent_key_fails(self, local_storage):
        """Test that deleting nonexistent key fails"""
        with pytest.raises(fortress.FortressError):
            await local_storage.delete("nonexistent_key")
    
    @pytest.mark.asyncio
    async def test_list_keys(self, local_storage, sample_data):
        """Test listing keys"""
        # Store multiple keys
        keys = ["key1", "key2", "key3"]
        for key in keys:
            await local_storage.store(key, sample_data)
        
        # List keys
        all_keys = await local_storage.list_keys()
        
        for key in keys:
            assert key in all_keys
        
        # Clean up
        for key in keys:
            await local_storage.delete(key)
    
    @pytest.mark.asyncio
    async def test_exists(self, local_storage, sample_data):
        """Test checking if key exists"""
        key = "test_key"
        
        # Check nonexistent key
        exists = await local_storage.exists(key)
        assert exists is False
        
        # Store data
        await local_storage.store(key, sample_data)
        
        # Check existing key
        exists = await local_storage.exists(key)
        assert exists is True
        
        # Clean up
        await local_storage.delete(key)
    
    @pytest.mark.asyncio
    async def test_large_data_storage(self, local_storage):
        """Test storing large data"""
        # 1MB of data
        large_data = b"A" * (1024 * 1024)
        key = "large_data_key"
        
        # Store large data
        await local_storage.store(key, large_data)
        
        # Retrieve and verify
        retrieved_data = await local_storage.retrieve(key)
        assert retrieved_data == large_data
        assert len(retrieved_data) == 1024 * 1024
        
        # Clean up
        await local_storage.delete(key)
    
    @pytest.mark.asyncio
    async def test_empty_data_storage(self, local_storage):
        """Test storing empty data"""
        key = "empty_data_key"
        empty_data = b""
        
        # Store empty data
        await local_storage.store(key, empty_data)
        
        # Retrieve and verify
        retrieved_data = await local_storage.retrieve(key)
        assert retrieved_data == empty_data
        
        # Clean up
        await local_storage.delete(key)
    
    @pytest.mark.asyncio
    async def test_binary_data_storage(self, local_storage):
        """Test storing binary data with null bytes"""
        key = "binary_data_key"
        binary_data = b"\x00\x01\x02\x03\x04\x05\xff\xfe\xfd"
        
        # Store binary data
        await local_storage.store(key, binary_data)
        
        # Retrieve and verify
        retrieved_data = await local_storage.retrieve(key)
        assert retrieved_data == binary_data
        
        # Clean up
        await local_storage.delete(key)
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self, local_storage, sample_data):
        """Test concurrent storage operations"""
        async def store_and_retrieve(key_suffix: str) -> bool:
            key = f"concurrent_key_{key_suffix}"
            await local_storage.store(key, sample_data)
            retrieved_data = await local_storage.retrieve(key)
            await local_storage.delete(key)
            return retrieved_data == sample_data
        
        # Run multiple operations concurrently
        tasks = [store_and_retrieve(str(i)) for i in range(10)]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            assert result is True


class TestStorageConfig:
    """Test storage configuration"""
    
    def test_create_local_config(self):
        """Test creating local storage configuration"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = fortress.create_local_config(temp_dir)
            
            assert isinstance(config, fortress.StorageConfigWrapper)
            assert config.backend_type == "local"
            assert config.path == temp_dir
    
    def test_create_s3_config(self):
        """Test creating S3 storage configuration"""
        config = fortress.create_s3_config(
            bucket="test-bucket",
            region="us-east-1",
            access_key="test-key",
            secret_key="test-secret"
        )
        
        assert isinstance(config, fortress.StorageConfigWrapper)
        assert config.backend_type == "s3"
        assert config.bucket == "test-bucket"
        assert config.region == "us-east-1"
    
    def test_create_azure_config(self):
        """Test creating Azure storage configuration"""
        config = fortress.create_azure_config(
            account="test-account",
            container="test-container",
            access_key="test-key"
        )
        
        assert isinstance(config, fortress.StorageConfigWrapper)
        assert config.backend_type == "azure"
        assert config.account == "test-account"
        assert config.container == "test-container"
    
    def test_config_validation(self):
        """Test configuration validation"""
        # Valid local config
        with tempfile.TemporaryDirectory() as temp_dir:
            config = fortress.create_local_config(temp_dir)
            assert config.is_valid()
        
        # Invalid local config (nonexistent path)
        with pytest.raises(fortress.FortressError):
            fortress.create_local_config("/nonexistent/path")


class TestStorageEncryption:
    """Test encrypted storage operations"""
    
    @pytest.mark.asyncio
    async def test_encrypted_storage(self, local_storage, sample_data):
        """Test storing encrypted data"""
        key = "encrypted_key"
        encryption_key = fortress.generate_key("aegis256")
        algorithm = fortress.EncryptionAlgorithm.aegis256()
        
        # Encrypt data
        encrypted_data = await algorithm.encrypt(sample_data, encryption_key)
        
        # Store encrypted data
        await local_storage.store(key, encrypted_data)
        
        # Retrieve and decrypt
        retrieved_encrypted = await local_storage.retrieve(key)
        decrypted_data = await algorithm.decrypt(retrieved_encrypted, encryption_key)
        
        assert decrypted_data == sample_data
        
        # Clean up
        await local_storage.delete(key)
    
    @pytest.mark.asyncio
    async def test_storage_with_key_manager(self, local_storage, sample_data):
        """Test storage operations with key manager"""
        key_manager = fortress.KeyManager()
        algorithm = fortress.EncryptionAlgorithm.aegis256()
        
        # Generate encryption key
        key_id = await key_manager.generate_key("aegis256", {
            "purpose": "storage-encryption",
            "tags": ["storage", "test"]
        })
        
        encryption_key = await key_manager.get_key(key_id)
        
        # Encrypt and store
        storage_key = "secure_data"
        encrypted_data = await algorithm.encrypt(sample_data, encryption_key)
        await local_storage.store(storage_key, encrypted_data)
        
        # Retrieve and decrypt
        retrieved_encrypted = await local_storage.retrieve(storage_key)
        decrypted_data = await algorithm.decrypt(retrieved_encrypted, encryption_key)
        
        assert decrypted_data == sample_data
        
        # Clean up
        await local_storage.delete(storage_key)
        await key_manager.delete_key(key_id)


class TestStoragePerformance:
    """Test storage performance characteristics"""
    
    @pytest.mark.asyncio
    async def test_batch_operations(self, local_storage, sample_data):
        """Test batch storage operations"""
        # Store multiple keys
        keys = [f"batch_key_{i}" for i in range(100)]
        
        # Batch store
        store_tasks = [
            local_storage.store(key, sample_data) 
            for key in keys
        ]
        await asyncio.gather(*store_tasks)
        
        # Batch retrieve
        retrieve_tasks = [
            local_storage.retrieve(key) 
            for key in keys
        ]
        results = await asyncio.gather(*retrieve_tasks)
        
        for result in results:
            assert result == sample_data
        
        # Batch delete
        delete_tasks = [
            local_storage.delete(key) 
            for key in keys
        ]
        await asyncio.gather(*delete_tasks)
    
    @pytest.mark.asyncio
    async def test_storage_performance_metrics(self, local_storage, sample_data):
        """Test storage performance metrics"""
        import time
        
        key = "performance_test"
        
        # Measure store time
        start_time = time.time()
        await local_storage.store(key, sample_data)
        store_time = time.time() - start_time
        
        # Measure retrieve time
        start_time = time.time()
        await local_storage.retrieve(key)
        retrieve_time = time.time() - start_time
        
        # Performance should be reasonable (less than 1 second for small data)
        assert store_time < 1.0
        assert retrieve_time < 1.0
        
        # Clean up
        await local_storage.delete(key)


if __name__ == "__main__":
    pytest.main([__file__])
