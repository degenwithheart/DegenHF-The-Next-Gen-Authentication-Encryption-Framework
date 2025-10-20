"""
DegenHF Flask ECC Authentication Package

Enhanced Flask authentication with ECC-based security, optimized for speed and performance.
"""

__version__ = "1.0.0"
__author__ = "DegenHF"
__email__ = "degenhf@example.com"

from .core import EccAuth, EccAuthHandler

__all__ = ["EccAuth", "EccAuthHandler"]