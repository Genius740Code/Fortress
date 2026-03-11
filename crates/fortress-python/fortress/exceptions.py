"""
Fortress Python SDK exceptions
"""

class FortressError(Exception):
    """
    Base exception class for Fortress SDK
    """
    
    def __init__(self, message, code=None, source=None):
        """
        Initialize Fortress error
        
        Args:
            message: Error message
            code: Error code (optional)
            source: Source exception (optional)
        """
        super().__init__(message)
        self.message = message
        self.code = code
        self.source = source
    
    def __str__(self):
        if self.code:
            return f"[{self.code}] {self.message}"
        return self.message


class FortressEncryptionError(FortressError):
    """Encryption-related errors"""
    pass


class FortressKeyError(FortressError):
    """Key management errors"""
    pass


class FortressStorageError(FortressError):
    """Storage-related errors"""
    pass


class FortressConfigError(FortressError):
    """Configuration errors"""
    pass
