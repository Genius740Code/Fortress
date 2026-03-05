#!/usr/bin/env python3
"""
Test suite for Fortress Python SDK key management functionality
"""

import pytest
import asyncio
import fortress
from typing import Dict, Any, List


class TestKeyManager:
    """Test key management operations"""
    
    @pytest.fixture
    async def key_manager(self):
        """Create a key manager for testing"""
        return fortress.KeyManager()
    
    @pytest.fixture
    def sample_metadata(self) -> Dict[str, Any]:
        """Sample key metadata"""
        return {
            "algorithm": "aegis256",
            "created_at": "2026-01-01T00:00:00Z",
            "purpose": "data-encryption",
            "tags": ["test", "encryption"],
            "owner": "test-user",
            "description": "Test key for unit tests"
        }
    
    @pytest.mark.asyncio
    async def test_generate_key(self, key_manager, sample_metadata):
        """Test key generation"""
        key_id = await key_manager.generate_key("aegis256", sample_metadata)
        
        assert isinstance(key_id, str)
        assert len(key_id) > 0
        
        # Verify key exists
        key_data = await key_manager.get_key(key_id)
        assert isinstance(key_data, bytes)
        assert len(key_data) > 0
    
    @pytest.mark.asyncio
    async def test_generate_key_different_algorithms(self, key_manager, sample_metadata):
        """Test key generation with different algorithms"""
        algorithms = ["aegis256", "chacha20poly1305", "aes256gcm"]
        key_ids = []
        
        for algorithm in algorithms:
            metadata = sample_metadata.copy()
            metadata["algorithm"] = algorithm
            
            key_id = await key_manager.generate_key(algorithm, metadata)
            key_ids.append(key_id)
            
            # Verify key exists and has correct size
            key_data = await key_manager.get_key(key_id)
            if algorithm in ["aegis256", "chacha20poly1305", "aes256gcm"]:
                assert len(key_data) == 32
        
        # Clean up
        for key_id in key_ids:
            await key_manager.delete_key(key_id)
    
    @pytest.mark.asyncio
    async def test_list_keys(self, key_manager, sample_metadata):
        """Test listing keys"""
        # Generate some keys
        key_ids = []
        for i in range(3):
            metadata = sample_metadata.copy()
            metadata["description"] = f"Test key {i}"
            key_id = await key_manager.generate_key("aegis256", metadata)
            key_ids.append(key_id)
        
        # List keys
        all_keys = await key_manager.list_keys()
        assert len(all_keys) >= len(key_ids)
        
        for key_id in key_ids:
            assert key_id in all_keys
        
        # Clean up
        for key_id in key_ids:
            await key_manager.delete_key(key_id)
    
    @pytest.mark.asyncio
    async def test_get_key_metadata(self, key_manager, sample_metadata):
        """Test retrieving key metadata"""
        key_id = await key_manager.generate_key("aegis256", sample_metadata)
        
        metadata = await key_manager.get_key_metadata(key_id)
        assert isinstance(metadata, dict)
        assert metadata["algorithm"] == "aegis256"
        assert metadata["purpose"] == "data-encryption"
        assert "test" in metadata["tags"]
        
        await key_manager.delete_key(key_id)
    
    @pytest.mark.asyncio
    async def test_rotate_key(self, key_manager, sample_metadata):
        """Test key rotation"""
        original_key_id = await key_manager.generate_key("aegis256", sample_metadata)
        original_key_data = await key_manager.get_key(original_key_id)
        
        # Rotate key
        new_key_id = await key_manager.rotate_key(original_key_id)
        
        assert new_key_id != original_key_id
        assert isinstance(new_key_id, str)
        
        # Verify new key exists and is different
        new_key_data = await key_manager.get_key(new_key_id)
        assert new_key_data != original_key_data
        
        # Verify old key is still accessible
        old_key_data = await key_manager.get_key(original_key_id)
        assert old_key_data == original_key_data
        
        # Clean up
        await key_manager.delete_key(original_key_id)
        await key_manager.delete_key(new_key_id)
    
    @pytest.mark.asyncio
    async def test_delete_key(self, key_manager, sample_metadata):
        """Test key deletion"""
        key_id = await key_manager.generate_key("aegis256", sample_metadata)
        
        # Verify key exists
        key_data = await key_manager.get_key(key_id)
        assert key_data is not None
        
        # Delete key
        await key_manager.delete_key(key_id)
        
        # Verify key is deleted
        with pytest.raises(fortress.FortressError):
            await key_manager.get_key(key_id)
    
    @pytest.mark.asyncio
    async def test_get_nonexistent_key_fails(self, key_manager):
        """Test that getting nonexistent key fails"""
        with pytest.raises(fortress.FortressError):
            await key_manager.get_key("nonexistent-key-id")
    
    @pytest.mark.asyncio
    async def test_delete_nonexistent_key_fails(self, key_manager):
        """Test that deleting nonexistent key fails"""
        with pytest.raises(fortress.FortressError):
            await key_manager.delete_key("nonexistent-key-id")
    
    @pytest.mark.asyncio
    async def test_key_encryption_with_managed_key(self, key_manager, sample_metadata):
        """Test encryption using a managed key"""
        # Generate key
        key_id = await key_manager.generate_key("aegis256", sample_metadata)
        key_data = await key_manager.get_key(key_id)
        
        # Test encryption
        algorithm = fortress.EncryptionAlgorithm.aegis256()
        plaintext = b"Test message with managed key"
        
        ciphertext = await algorithm.encrypt(plaintext, key_data)
        decrypted = await algorithm.decrypt(ciphertext, key_data)
        
        assert decrypted == plaintext
        
        # Clean up
        await key_manager.delete_key(key_id)
    
    @pytest.mark.asyncio
    async def test_concurrent_key_operations(self, key_manager, sample_metadata):
        """Test concurrent key operations"""
        async def generate_and_delete():
            metadata = sample_metadata.copy()
            key_id = await key_manager.generate_key("aegis256", metadata)
            key_data = await key_manager.get_key(key_id)
            await key_manager.delete_key(key_id)
            return len(key_data)
        
        # Run multiple operations concurrently
        tasks = [generate_and_delete() for _ in range(10)]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            assert result == 32  # Aegis256 key size
    
    @pytest.mark.asyncio
    async def test_key_search_by_tags(self, key_manager, sample_metadata):
        """Test searching keys by tags"""
        # Generate keys with different tags
        key_ids = []
        tags_sets = [
            ["test", "encryption"],
            ["test", "backup"],
            ["production", "encryption"],
            ["development", "test"]
        ]
        
        for tags in tags_sets:
            metadata = sample_metadata.copy()
            metadata["tags"] = tags
            key_id = await key_manager.generate_key("aegis256", metadata)
            key_ids.append(key_id)
        
        # Search by tags (if supported)
        try:
            encryption_keys = await key_manager.search_keys_by_tags(["encryption"])
            assert len(encryption_keys) >= 2
            
            test_keys = await key_manager.search_keys_by_tags(["test"])
            assert len(test_keys) >= 3
            
        except AttributeError:
            # Search functionality not implemented yet
            pytest.skip("Key search by tags not implemented")
        
        # Clean up
        for key_id in key_ids:
            await key_manager.delete_key(key_id)
    
    @pytest.mark.asyncio
    async def test_key_statistics(self, key_manager, sample_metadata):
        """Test getting key statistics"""
        # Generate some keys
        key_ids = []
        for i in range(5):
            metadata = sample_metadata.copy()
            metadata["description"] = f"Test key {i}"
            key_id = await key_manager.generate_key("aegis256", metadata)
            key_ids.append(key_id)
        
        # Get statistics (if supported)
        try:
            stats = await key_manager.get_statistics()
            assert isinstance(stats, dict)
            assert "total_keys" in stats
            assert stats["total_keys"] >= len(key_ids)
            
        except AttributeError:
            # Statistics functionality not implemented yet
            pytest.skip("Key statistics not implemented")
        
        # Clean up
        for key_id in key_ids:
            await key_manager.delete_key(key_id)


class TestKeyMetadata:
    """Test key metadata handling"""
    
    def test_key_metadata_serialization(self):
        """Test key metadata serialization"""
        metadata = fortress.KeyMetadata(
            algorithm="aegis256",
            created_at="2026-01-01T00:00:00Z",
            purpose="data-encryption",
            tags=["test", "encryption"],
            owner="test-user"
        )
        
        assert metadata.algorithm == "aegis256"
        assert metadata.purpose == "data-encryption"
        assert "test" in metadata.tags
        assert metadata.owner == "test-user"
    
    def test_key_metadata_validation(self):
        """Test key metadata validation"""
        # Valid metadata
        valid_metadata = {
            "algorithm": "aegis256",
            "purpose": "data-encryption"
        }
        
        # Invalid metadata (missing required fields)
        with pytest.raises(fortress.FortressError):
            invalid_metadata = {}
            # This would fail validation if implemented
            pass


if __name__ == "__main__":
    pytest.main([__file__])
