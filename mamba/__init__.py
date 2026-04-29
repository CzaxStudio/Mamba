# mamba/__init__.py
"""
Mamba - Powerful OSINT library for Python
"""

from .core import MambaClient, OSINTResult
from .modules import (
    EmailReputation,
    DomainIntel,
    UsernameSearch,
    PhoneLookup,
    IPInvestigator
)
from .utils import CacheManager, ResultFormatter, BatchProcessor

__version__ = "1.0.0"
__all__ = [
    "MambaClient",
    "OSINTResult", 
    "EmailReputation",
    "DomainIntel",
    "UsernameSearch",
    "PhoneLookup",
    "IPInvestigator",
    "CacheManager",
    "ResultFormatter",
    "BatchProcessor"
]

def create_client(api_keys=None, rate_limit=1.0):
    return MambaClient(api_keys=api_keys or {}, rate_limit=rate_limit)