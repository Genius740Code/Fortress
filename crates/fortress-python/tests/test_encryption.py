#!/usr/bin/env python3
"""
Test suite for Fortress Python SDK encryption functionality
"""

import pytest
import asyncio
import fortress
from typing import List, Tuple


class TestEncryption:
    """Test encryption algorithms and operations"""
    
    @pytest.fixture
    def algorithms(self) -> List[str]:
        """Get list of available algorithms"""
        return fortress.list_algorithms()
    
    @pytest.fixture
    def test_data(self) -> bytes:
        """Test data for encryption"""
        return b"Hello, Fortress! This is a test message for encryption."
    
    @pytest.mark.asyncio
    async def test_algorithm_creation(self, algorithms):
        """Test creating encryption algorithms"""
        for alg_name in algorithms:
            try:
                if alg_name == "aegis256":
                    algorithm = fortress.EncryptionAlgorithm.aegis256()
                elif alg_name == "chacha20poly1305":
                    algorithm = fortress.EncryptionAlgorithm.chacha20poly1305()
                elif alg_name == "aes256gcm":
                    algorithm = fortress.EncryptionAlgorithm.aes256gcm()
                elif alg_name == "xchacha20poly1305":
                    algorithm = fortress.EncryptionAlgorithm.xchacha20poly1305()
                elif alg_name == "blake3_encrypt":
                    algorithm = fortress.EncryptionAlgorithm.blake3_encrypt()
                elif alg_name == "hmacsha512_encrypt":
                    algorithm = fortress.EncryptionAlgorithm.hmacsha512_encrypt()
                elif alg_name == "aes256ctr":
                    algorithm = fortress.EncryptionAlgorithm.aes256ctr()
                elif alg_name == "argon2id_encrypt":
                    algorithm = fortress.EncryptionAlgorithm.argon2id_encrypt()
                elif alg_name == "composite_encrypt":
                    algorithm = fortress.EncryptionAlgorithm.composite_encrypt()
                else:
                    pytest.skip(f"Unknown algorithm: {alg_name}")
                
                assert algorithm.algorithm_name() == alg_name
                assert algorithm.key_size() > 0
                assert algorithm.nonce_size() > 0
                assert algorithm.tag_size() > 0
                
            except Exception as e:
                pytest.fail(f"Failed to create algorithm {alg_name}: {e}")
    
    @pytest.mark.asyncio
    async def test_key_generation(self, algorithms):
        """Test key generation for different algorithms"""
        for alg_name in algorithms[:3]:  # Test first 3 algorithms
            key = fortress.generate_key(alg_name)
            assert isinstance(key, bytes)
            assert len(key) > 0
            
            # Test key size matches algorithm requirements
            if alg_name == "aegis256":
                assert len(key) == 32
            elif alg_name == "chacha20poly1305":
                assert len(key) == 32
            elif alg_name == "aes256gcm":
                assert len(key) == 32
    
    @pytest.mark.asyncio
    async def test_encrypt_decrypt_roundtrip(self, algorithms, test_data):
        """Test encryption and decryption roundtrip"""
        # Test with a few algorithms
        test_algorithms = ["aegis256", "chacha20poly1305", "aes256gcm"]
        
        for alg_name in test_algorithms:
            if alg_name not in algorithms:
                pytest.skip(f"Algorithm {alg_name} not available")
            
            # Create algorithm
            if alg_name == "aegis256":
                algorithm = fortress.EncryptionAlgorithm.aegis256()
            elif alg_name == "chacha20poly1305":
                algorithm = fortress.EncryptionAlgorithm.chacha20poly1305()
            elif alg_name == "aes256gcm":
                algorithm = fortress.EncryptionAlgorithm.aes256gcm()
            else:
                continue
            
            # Generate key
            key = fortress.generate_key(alg_name)
            
            # Encrypt
            ciphertext = await algorithm.encrypt(test_data, key)
            assert isinstance(ciphertext, bytes)
            assert len(ciphertext) > len(test_data)
            assert ciphertext != test_data
            
            # Decrypt
            plaintext = await algorithm.decrypt(ciphertext, key)
            assert plaintext == test_data
    
    @pytest.mark.asyncio
    async def test_encrypt_with_different_keys(self, test_data):
        """Test that different keys produce different ciphertexts"""
        algorithm = fortress.EncryptionAlgorithm.aegis256()
        key1 = fortress.generate_key("aegis256")
        key2 = fortress.generate_key("aegis256")
        
        ciphertext1 = await algorithm.encrypt(test_data, key1)
        ciphertext2 = await algorithm.encrypt(test_data, key2)
        
        assert ciphertext1 != ciphertext2
    
    @pytest.mark.asyncio
    async def test_decrypt_with_wrong_key_fails(self, test_data):
        """Test that decryption fails with wrong key"""
        algorithm = fortress.EncryptionAlgorithm.aegis256()
        key1 = fortress.generate_key("aegis256")
        key2 = fortress.generate_key("aegis256")
        
        ciphertext = await algorithm.encrypt(test_data, key1)
        
        with pytest.raises(fortress.FortressError):
            await algorithm.decrypt(ciphertext, key2)
    
    @pytest.mark.asyncio
    async def test_decrypt_modified_data_fails(self, test_data):
        """Test that decryption fails with modified ciphertext"""
        algorithm = fortress.EncryptionAlgorithm.aegis256()
        key = fortress.generate_key("aegis256")
        
        ciphertext = await algorithm.encrypt(test_data, key)
        
        # Modify ciphertext
        modified = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])
        
        with pytest.raises(fortress.FortressError):
            await algorithm.decrypt(modified, key)
    
    @pytest.mark.asyncio
    async def test_empty_data_encryption(self):
        """Test encrypting empty data"""
        algorithm = fortress.EncryptionAlgorithm.aegis256()
        key = fortress.generate_key("aegis256")
        
        ciphertext = await algorithm.encrypt(b"", key)
        plaintext = await algorithm.decrypt(ciphertext, key)
        assert plaintext == b""
    
    @pytest.mark.asyncio
    async def test_large_data_encryption(self):
        """Test encrypting large data"""
        algorithm = fortress.EncryptionAlgorithm.aegis256()
        key = fortress.generate_key("aegis256")
        
        # 1MB of data
        large_data = b"A" * (1024 * 1024)
        
        ciphertext = await algorithm.encrypt(large_data, key)
        plaintext = await algorithm.decrypt(ciphertext, key)
        assert plaintext == large_data
    
    def test_nonce_generation(self):
        """Test nonce generation"""
        for alg_name in ["aegis256", "chacha20poly1305", "aes256gcm"]:
            nonce = fortress.generate_nonce(alg_name)
            assert isinstance(nonce, bytes)
            assert len(nonce) > 0
            
            # Test that nonces are unique
            nonce2 = fortress.generate_nonce(alg_name)
            assert nonce != nonce2
    
    @pytest.mark.asyncio
    async def test_concurrent_encryption(self, test_data):
        """Test concurrent encryption operations"""
        algorithm = fortress.EncryptionAlgorithm.aegis256()
        key = fortress.generate_key("aegis256")
        
        async def encrypt_decrypt(data: bytes) -> bytes:
            ciphertext = await algorithm.encrypt(data, key)
            return await algorithm.decrypt(ciphertext, key)
        
        # Run multiple encryption/decryption operations concurrently
        tasks = [encrypt_decrypt(test_data) for _ in range(10)]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            assert result == test_data


class TestEncryptionProfiles:
    """Test encryption profiles and configurations"""
    
    def test_create_encryption_profile(self):
        """Test creating encryption profiles"""
        profile = fortress.EncryptionProfile("aegis256", {"key_rotation_days": 90})
        assert profile.algorithm == "aegis256"
        assert profile.config["key_rotation_days"] == 90
    
    @pytest.mark.asyncio
    async def test_profile_encryption(self):
        """Test encryption using profiles"""
        profile = fortress.EncryptionProfile("aegis256", {"key_rotation_days": 90})
        key = fortress.generate_key("aegis256")
        data = b"Test data for profile encryption"
        
        ciphertext = await profile.encrypt(data, key)
        plaintext = await profile.decrypt(ciphertext, key)
        assert plaintext == data


if __name__ == "__main__":
    pytest.main([__file__])
