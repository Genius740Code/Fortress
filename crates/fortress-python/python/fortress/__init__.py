"""
Fortress Python SDK

A Python interface to the Fortress secure database system, providing
enterprise-grade encryption, key management, and multi-tenant isolation.

Example usage:
    import fortress
    
    # Create configuration
    config = fortress.FortressConfig.lightning()
    
    # Initialize encryption
    algorithm = fortress.EncryptionAlgorithm.aegis256()
    key = fortress.generate_key("aegis256")
    
    # Encrypt and decrypt data
    ciphertext = algorithm.encrypt(b"Hello, Fortress!", key)
    plaintext = algorithm.decrypt(ciphertext, key)
"""

from ._fortress import (
    # Version information
    __version__,
    __build_timestamp__,
    __git_sha__,
    __rust_version__,
    __target__,

    # Core classes
    FortressConfig,
    EncryptionAlgorithm,
    KeyManager,
    StorageBackend,
    PolicyEngine,
    AuditLogger,
    TenantManager,
    FortressError,

    # Utility functions
    get_version,
    get_build_info,
    list_algorithms,
    create_config,
)

# Import submodules
try:
    from . import encryption
    from . import key_management
    from . import storage
    from . import config as config_module
    from . import audit
    from . import policy
    from . import tenant
    from . import error
except ImportError:
    # Submodules may not be available in all builds
    pass

# Convenience imports
from .encryption import EncryptionProfile, generate_key, generate_nonce
from .key_management import KeyMetadata
from .storage import StorageConfigWrapper, create_local_config, create_s3_config, create_azure_config
from .config import list_performance_profiles, list_security_levels, list_encryption_algorithms, create_custom_config
from .audit import AuditConfigWrapper, AuditEntryWrapper
from .policy import RoleWrapper, PermissionWrapper, ResourceWrapper
from .tenant import (
    TenantWrapper, 
    CreateTenantRequestWrapper, 
    UpdateTenantRequestWrapper,
    TenantResourceLimitsWrapper,
    TenantStatsWrapper
)

# Re-export commonly used functions
from .encryption import *
from .key_management import *
from .storage import *
from .config import *
from .audit import *
from .policy import *
from .tenant import *

# Package metadata
__author__ = "Fortress Team <team@fortress-db.com>"
__license__ = "Apache-2.0"
__description__ = "Python SDK for Fortress secure database system"
__url__ = "https://github.com/Genius740Code/Fortress"
__email__ = "team@fortress-db.com"

# Version compatibility
__python_requires__ = ">=3.8"

# Supported platforms
__platforms__ = ["linux", "darwin", "win32"]

def get_supported_features():
    """Get a list of supported Fortress features in this build."""
    return [
        "encryption",
        "key_management", 
        "storage",
        "configuration",
        "audit_logging",
        "policy_engine",
        "multi_tenant",
        "error_handling",
    ]

def check_compatibility():
    """Check if the current environment is compatible with Fortress."""
    import sys
    if sys.version_info < (3, 8):
        raise RuntimeError("Fortress requires Python 3.8 or higher")
    return True

# Auto-check compatibility on import
try:
    check_compatibility()
except Exception as e:
    import warnings
    warnings.warn(f"Fortress compatibility check failed: {e}")

# Export all public symbols
__all__ = [
    # Version info
    "__version__",
    "__build_timestamp__", 
    "__git_sha__",
    "__rust_version__",
    "__target__",
    
    # Core classes
    "FortressConfig",
    "EncryptionAlgorithm", 
    "KeyManager",
    "StorageBackend",
    "PolicyEngine",
    "AuditLogger",
    "TenantManager",
    "FortressError",
    
    # Utility functions
    "get_version",
    "get_build_info", 
    "list_algorithms",
    "create_config",
    
    # Encryption
    "EncryptionProfile",
    "generate_key",
    "generate_nonce",
    
    # Key management
    "KeyMetadata",
    
    # Storage
    "StorageConfigWrapper",
    "create_local_config",
    "create_s3_config", 
    "create_azure_config",
    
    # Configuration
    "list_performance_profiles",
    "list_security_levels",
    "list_encryption_algorithms",
    "create_custom_config",
    
    # Audit
    "AuditConfigWrapper",
    "AuditEntryWrapper",
    
    # Policy
    "RoleWrapper",
    "PermissionWrapper", 
    "ResourceWrapper",
    
    # Tenant
    "TenantWrapper",
    "CreateTenantRequestWrapper",
    "UpdateTenantRequestWrapper",
    "TenantResourceLimitsWrapper",
    "TenantStatsWrapper",
    
    # Utilities
    "get_supported_features",
    "check_compatibility",
]
