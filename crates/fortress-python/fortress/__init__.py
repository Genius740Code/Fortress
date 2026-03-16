"""
Fortress Python SDK - Production-ready secure database client
"""

__version__ = "0.1.0"
__author__ = "Fortress Team"
__email__ = "team@fortress-db.com"

from .client import (
    Fortress, 
    SecurityConfig, 
    PerformanceConfig,
    RateLimiter,
    ConnectionPool,
    DataCache
)
from .exceptions import (
    FortressError,
    FortressEncryptionError,
    FortressKeyError,
    FortressStorageError,
    FortressConfigError
)

__all__ = [
    "Fortress",
    "SecurityConfig", 
    "PerformanceConfig",
    "RateLimiter",
    "ConnectionPool",
    "DataCache",
    "FortressError",
    "FortressEncryptionError",
    "FortressKeyError", 
    "FortressStorageError",
    "FortressConfigError"
]
