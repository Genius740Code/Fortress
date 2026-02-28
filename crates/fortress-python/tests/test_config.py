#!/usr/bin/env python3
"""
Test suite for Fortress Python SDK configuration functionality
"""

import pytest
import fortress
from typing import Dict, Any, List


class TestFortressConfig:
    """Test Fortress configuration"""
    
    def test_create_default_config(self):
        """Test creating default configuration"""
        config = fortress.create_config()
        
        assert isinstance(config, fortress.FortressConfig)
        assert config is not None
    
    def test_create_lightning_config(self):
        """Test creating lightning configuration"""
        config = fortress.create_config("lightning")
        
        assert isinstance(config, fortress.FortressConfig)
        assert config.profile == "lightning"
    
    def test_create_balanced_config(self):
        """Test creating balanced configuration"""
        config = fortress.create_config("balanced")
        
        assert isinstance(config, fortress.FortressConfig)
        assert config.profile == "balanced"
    
    def test_create_fortress_config(self):
        """Test creating fortress configuration"""
        config = fortress.create_config("fortress")
        
        assert isinstance(config, fortress.FortressConfig)
        assert config.profile == "fortress"
    
    def test_create_startup_config(self):
        """Test creating startup configuration"""
        config = fortress.create_config("startup")
        
        assert isinstance(config, fortress.FortressConfig)
        assert config.profile == "startup"
    
    def test_create_enterprise_config(self):
        """Test creating enterprise configuration"""
        config = fortress.create_config("enterprise")
        
        assert isinstance(config, fortress.FortressConfig)
        assert config.profile == "enterprise"
    
    def test_create_invalid_config(self):
        """Test creating configuration with invalid profile"""
        config = fortress.create_config("invalid_profile")
        
        # Should fall back to default
        assert isinstance(config, fortress.FortressConfig)
        assert config.profile in ["lightning", "balanced", "fortress", "startup", "enterprise", "default"]
    
    def test_config_serialization(self):
        """Test configuration serialization"""
        config = fortress.create_config("fortress")
        
        # Convert to dict
        config_dict = config.to_dict()
        assert isinstance(config_dict, dict)
        assert "profile" in config_dict
        assert "encryption" in config_dict
        assert "storage" in config_dict
        assert "audit" in config_dict
    
    def test_config_from_dict(self):
        """Test creating configuration from dict"""
        config_dict = {
            "profile": "custom",
            "encryption": {
                "default_algorithm": "aegis256",
                "key_rotation_days": 90
            },
            "storage": {
                "backend": "local",
                "path": "/tmp/fortress"
            }
        }
        
        config = fortress.FortressConfig.from_dict(config_dict)
        assert config.profile == "custom"
        assert config.encryption["default_algorithm"] == "aegis256"
        assert config.encryption["key_rotation_days"] == 90


class TestPerformanceProfiles:
    """Test performance profiles"""
    
    def test_list_performance_profiles(self):
        """Test listing available performance profiles"""
        profiles = fortress.list_performance_profiles()
        
        assert isinstance(profiles, list)
        assert len(profiles) > 0
        assert "lightning" in profiles
        assert "balanced" in profiles
        assert "fortress" in profiles
        assert "startup" in profiles
        assert "enterprise" in profiles
    
    def test_profile_characteristics(self):
        """Test profile characteristics"""
        profiles = fortress.list_performance_profiles()
        
        for profile in profiles:
            config = fortress.create_config(profile)
            
            # Each profile should have valid configuration
            assert config.encryption is not None
            assert config.storage is not None
            assert config.audit is not None
            
            # Check profile-specific settings
            if profile == "lightning":
                # Lightning should prioritize speed
                assert config.encryption.get("default_algorithm") in ["chacha20poly1305", "aegis256"]
            elif profile == "fortress":
                # Fortress should prioritize security
                assert config.encryption.get("default_algorithm") in ["aegis256", "composite_encrypt"]
            elif profile == "startup":
                # Startup should be lightweight
                assert config.audit.get("enabled") is False or config.audit.get("level") == "minimal"


class TestSecurityLevels:
    """Test security levels"""
    
    def test_list_security_levels(self):
        """Test listing available security levels"""
        levels = fortress.list_security_levels()
        
        assert isinstance(levels, list)
        assert len(levels) > 0
        assert "minimal" in levels
        assert "standard" in levels
        assert "high" in levels
        assert "maximum" in levels
    
    def test_security_level_configurations(self):
        """Test security level configurations"""
        levels = fortress.list_security_levels()
        
        for level in levels:
            config = fortress.create_custom_config(security_level=level)
            
            # Each level should have valid configuration
            assert config.encryption is not None
            assert config.storage is not None
            
            # Check level-specific settings
            if level == "minimal":
                # Minimal security should have basic encryption
                assert config.encryption.get("default_algorithm") is not None
            elif level == "maximum":
                # Maximum security should have strongest settings
                assert config.encryption.get("default_algorithm") in ["aegis256", "composite_encrypt"]
                assert config.audit.get("enabled") is True


class TestEncryptionAlgorithms:
    """Test encryption algorithm configurations"""
    
    def test_list_encryption_algorithms(self):
        """Test listing available encryption algorithms"""
        algorithms = fortress.list_encryption_algorithms()
        
        assert isinstance(algorithms, list)
        assert len(algorithms) > 0
        assert "aegis256" in algorithms
        assert "chacha20poly1305" in algorithms
        assert "aes256gcm" in algorithms
        assert "xchacha20poly1305" in algorithms
    
    def test_algorithm_configurations(self):
        """Test algorithm-specific configurations"""
        algorithms = fortress.list_encryption_algorithms()
        
        for algorithm in algorithms:
            config = fortress.create_custom_config(
                encryption_algorithm=algorithm,
                security_level="standard"
            )
            
            assert config.encryption["default_algorithm"] == algorithm
            
            # Check algorithm-specific settings
            if algorithm == "aegis256":
                assert config.encryption.get("key_size") == 32
            elif algorithm == "chacha20poly1305":
                assert config.encryption.get("key_size") == 32
            elif algorithm == "aes256gcm":
                assert config.encryption.get("key_size") == 32


class TestCustomConfigurations:
    """Test custom configuration creation"""
    
    def test_create_custom_config_all_parameters(self):
        """Test creating custom configuration with all parameters"""
        config = fortress.create_custom_config(
            performance_profile="balanced",
            security_level="high",
            encryption_algorithm="aegis256",
            storage_backend="local",
            audit_enabled=True,
            audit_level="detailed"
        )
        
        assert config.encryption["default_algorithm"] == "aegis256"
        assert config.storage["backend"] == "local"
        assert config.audit["enabled"] is True
        assert config.audit["level"] == "detailed"
    
    def test_create_custom_config_partial_parameters(self):
        """Test creating custom configuration with partial parameters"""
        config = fortress.create_custom_config(
            encryption_algorithm="chacha20poly1305",
            audit_enabled=True
        )
        
        assert config.encryption["default_algorithm"] == "chacha20poly1305"
        assert config.audit["enabled"] is True
        # Other settings should use defaults
    
    def test_config_validation(self):
        """Test configuration validation"""
        # Valid configuration
        config = fortress.create_config("fortress")
        assert config.is_valid()
        
        # Invalid configuration (if validation is implemented)
        # This would test for missing required fields, invalid values, etc.
    
    def test_config_merge(self):
        """Test merging configurations"""
        base_config = fortress.create_config("balanced")
        override_config = fortress.create_custom_config(
            encryption_algorithm="aegis256",
            audit_enabled=False
        )
        
        # Merge configurations
        merged = base_config.merge(override_config)
        
        assert merged.encryption["default_algorithm"] == "aegis256"
        assert merged.audit["enabled"] is False
        # Other settings should come from base config


class TestConfigurationPersistence:
    """Test configuration persistence"""
    
    def test_save_and_load_config(self):
        """Test saving and loading configuration"""
        config = fortress.create_config("enterprise")
        
        # Save to file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config.save_to_file(f.name)
            temp_file = f.name
        
        try:
            # Load from file
            loaded_config = fortress.FortressConfig.load_from_file(temp_file)
            
            assert loaded_config.profile == config.profile
            assert loaded_config.encryption == config.encryption
            assert loaded_config.storage == config.storage
            assert loaded_config.audit == config.audit
            
        finally:
            os.unlink(temp_file)
    
    def test_config_environment_variables(self):
        """Test configuration from environment variables"""
        # Set environment variables
        os.environ['FORTRESS_PROFILE'] = 'lightning'
        os.environ['FORTRESS_ENCRYPTION_ALGORITHM'] = 'aegis256'
        os.environ['FORTRESS_AUDIT_ENABLED'] = 'true'
        
        try:
            # Load config from environment
            config = fortress.FortressConfig.from_environment()
            
            assert config.profile == 'lightning'
            assert config.encryption['default_algorithm'] == 'aegis256'
            assert config.audit['enabled'] is True
            
        finally:
            # Clean up environment variables
            os.environ.pop('FORTRESS_PROFILE', None)
            os.environ.pop('FORTRESS_ENCRYPTION_ALGORITHM', None)
            os.environ.pop('FORTRESS_AUDIT_ENABLED', None)


class TestConfigurationTemplates:
    """Test configuration templates"""
    
    def test_development_template(self):
        """Test development configuration template"""
        config = fortress.create_config("startup")  # Startup is good for development
        
        assert config.encryption is not None
        assert config.storage is not None
        # Development should have minimal overhead
        assert config.audit.get("enabled", True) is False or config.audit.get("level") == "minimal"
    
    def test_production_template(self):
        """Test production configuration template"""
        config = fortress.create_config("fortress")  # Fortress is good for production
        
        assert config.encryption is not None
        assert config.storage is not None
        # Production should have full audit and security
        assert config.audit.get("enabled") is True
        assert config.encryption.get("default_algorithm") in ["aegis256", "composite_encrypt"]
    
    def test_testing_template(self):
        """Test testing configuration template"""
        config = fortress.create_custom_config(
            performance_profile="lightning",
            security_level="minimal",
            audit_enabled=False
        )
        
        # Testing should be fast and lightweight
        assert config.encryption.get("default_algorithm") in ["chacha20poly1305"]
        assert config.audit.get("enabled") is False


if __name__ == "__main__":
    pytest.main([__file__])
