"""
Fortress Python SDK - Simple wrapper for demonstration
"""

__version__ = "0.1.0"
__author__ = "Fortress Team"
__email__ = "team@fortress-db.com"

from .client import Fortress
from .exceptions import FortressError

__all__ = ["Fortress", "FortressError"]
