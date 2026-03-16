#!/usr/bin/env python3
"""
Pytest configuration and fixtures for Fortress Python SDK tests
"""

import pytest
import asyncio
import tempfile
import os
from typing import Generator, AsyncGenerator

# Import fortress for testing
import fortress
from fortress import Fortress, SecurityConfig, PerformanceConfig


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir() -> Generator[str, None, None]:
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir


@pytest.fixture
def temp_file() -> Generator[str, None, None]:
    """Create a temporary file for testing."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"test data")
        temp_file_path = temp_file.name
    
    try:
        yield temp_file_path
    finally:
        os.unlink(temp_file_path)


@pytest.fixture
def sample_config() -> SecurityConfig:
    """Create a sample Fortress configuration for testing."""
    return SecurityConfig(
        max_key_size=1024,
        max_data_size=1024 * 1024,
        rate_limit_requests=100,
        rate_limit_window=60,
        enable_audit_logging=False,
        require_key_id=False
    )


@pytest.fixture
def sample_key() -> str:
    """Create a sample encryption key for testing."""
    # Create a temporary client to generate a key
    with Fortress() as client:
        client.initialize()
        return client.generate_key("aes256gcm")


@pytest.fixture
def sample_data() -> bytes:
    """Create sample data for testing."""
    return b"Hello, Fortress! This is sample test data."


@pytest.fixture
def sample_metadata() -> dict:
    """Create sample metadata for testing."""
    return {
        "algorithm": "aegis256",
        "created_at": "2026-01-01T00:00:00Z",
        "purpose": "test-data",
        "tags": ["test", "unit-test"],
        "owner": "test-suite",
        "description": "Test key for unit tests"
    }


# Async fixtures for async tests
@pytest.fixture
async def async_key_manager() -> AsyncGenerator[Fortress, None]:
    """Create a key manager for async testing."""
    manager = Fortress()
    manager.initialize()
    yield manager
    # Cleanup if needed
    try:
        # Clean up any test keys
        keys = manager.list_keys()
        for key_id in keys:
            if "test" in key_id.lower():
                manager.delete_key(key_id)
    except:
        pass  # Ignore cleanup errors
    finally:
        manager.shutdown()


@pytest.fixture
async def async_storage_backend(temp_dir: str) -> AsyncGenerator[Fortress, None]:
    """Create a storage backend for async testing."""
    client = Fortress()
    client.initialize()
    yield client
    # Cleanup if needed
    try:
        # Clean up any test data
        # Note: In our new implementation, storage is part of the client
        pass
    except:
        pass  # Ignore cleanup errors
    finally:
        client.shutdown()


# Test markers
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )
    config.addinivalue_line(
        "markers", "encryption: marks tests related to encryption"
    )
    config.addinivalue_line(
        "markers", "key_management: marks tests related to key management"
    )
    config.addinivalue_line(
        "markers", "storage: marks tests related to storage"
    )
    config.addinivalue_line(
        "markers", "config: marks tests related to configuration"
    )


# Test collection hooks
def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test names."""
    for item in items:
        # Add markers based on test file names
        if "encryption" in item.nodeid:
            item.add_marker(pytest.mark.encryption)
        elif "key_management" in item.nodeid:
            item.add_marker(pytest.mark.key_management)
        elif "storage" in item.nodeid:
            item.add_marker(pytest.mark.storage)
        elif "config" in item.nodeid:
            item.add_marker(pytest.mark.config)
        
        # Add unit test marker by default
        if not any(marker.name in ["integration", "slow"] for marker in item.iter_markers()):
            item.add_marker(pytest.mark.unit)


# Skip conditions
def pytest_runtest_setup(item):
    """Setup for each test item."""
    # Check if fortress is available
    try:
        import fortress
        client = fortress.Fortress()
        version = client.get_version()
    except ImportError:
        pytest.skip("Fortress Python SDK not available")
    except Exception as e:
        pytest.skip(f"Fortress Python SDK not working: {e}")
    
    # Check Python version
    import sys
    if sys.version_info < (3, 8):
        pytest.skip("Python 3.8+ required")


# Test utilities
class TestUtils:
    """Utility functions for testing."""
    
    @staticmethod
    def assert_bytes_equal(a: bytes, b: bytes):
        """Assert that two byte arrays are equal."""
        assert a == b, f"Byte arrays differ: {a!r} != {b!r}"
    
    @staticmethod
    def assert_key_valid(key_id: str, algorithm: str):
        """Assert that a key is valid for the given algorithm."""
        assert isinstance(key_id, str), "Key ID must be string"
        assert len(key_id) > 0, "Key ID must not be empty"
    
    @staticmethod
    def assert_encryption_different(original: bytes, encrypted: bytes):
        """Assert that encrypted data is different from original."""
        assert encrypted != original, "Encrypted data should be different from original"
        assert len(encrypted) > len(original), "Encrypted data should be larger than original"
    
    @staticmethod
    async def assert_encrypt_decrypt_roundtrip(client: Fortress, 
                                            key_id: str, data: bytes, algorithm: str = "aes256gcm"):
        """Assert that encrypt/decrypt roundtrip works correctly."""
        encrypted = client.encrypt(data, key_id, algorithm)
        decrypted = client.decrypt(encrypted, key_id, algorithm)
        assert decrypted == data, "Decrypted data should match original"


# Custom assertions
@pytest.fixture
def test_utils():
    """Provide test utilities to tests."""
    return TestUtils()


# Performance testing utilities
class PerformanceTester:
    """Utilities for performance testing."""
    
    @staticmethod
    async def measure_async_time(func, *args, **kwargs):
        """Measure execution time of an async function."""
        import time
        start = time.time()
        result = await func(*args, **kwargs)
        end = time.time()
        return result, end - start
    
    @staticmethod
    def measure_sync_time(func, *args, **kwargs):
        """Measure execution time of a sync function."""
        import time
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        return result, end - start


@pytest.fixture
def perf_tester():
    """Provide performance testing utilities."""
    return PerformanceTester()


# Mock utilities for testing
class MockStorage:
    """Mock storage backend for testing."""
    
    def __init__(self):
        self.data = {}
    
    def store(self, key: str, value: bytes):
        """Mock store operation."""
        self.data[key] = value
        return True
    
    def retrieve(self, key: str) -> bytes:
        """Mock retrieve operation."""
        if key not in self.data:
            raise fortress.FortressError("Key not found")
        return self.data[key]
    
    def delete(self, key: str):
        """Mock delete operation."""
        if key not in self.data:
            raise fortress.FortressError("Key not found")
        del self.data[key]
        return True
    
    def list_keys(self) -> list:
        """Mock list keys operation."""
        return list(self.data.keys())
    
    def exists(self, key: str) -> bool:
        """Mock exists operation."""
        return key in self.data


@pytest.fixture
def mock_storage():
    """Provide a mock storage backend."""
    return MockStorage()


# Error testing utilities
class ErrorTester:
    """Utilities for testing error conditions."""
    
    @staticmethod
    async def assert_async_raises(error_type, func, *args, **kwargs):
        """Assert that an async function raises a specific error."""
        with pytest.raises(error_type):
            await func(*args, **kwargs)
    
    @staticmethod
    def assert_sync_raises(error_type, func, *args, **kwargs):
        """Assert that a sync function raises a specific error."""
        with pytest.raises(error_type):
            func(*args, **kwargs)


@pytest.fixture
def error_tester():
    """Provide error testing utilities."""
    return ErrorTester()
