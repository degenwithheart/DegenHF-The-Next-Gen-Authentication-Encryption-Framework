"""
DegenHF FastAPI ECC Authentication Package

Enhanced FastAPI authentication with ECC-based security, optimized for speed and performance.
"""

__version__ = "1.0.0"
__author__ = "DegenHF"
__email__ = "degenhf@example.com"

from .core import EccAuthHandler, get_current_user

__all__ = ["EccAuthHandler", "get_current_user"]