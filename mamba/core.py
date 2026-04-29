"""
Core client, configuration management, and base classes
"""

import hashlib
import json
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class OSINTResult:
    """Standardized result object for all OSINT queries"""
    success: bool
    data: Dict[str, Any]
    source: str
    query: str
    timestamp: datetime = field(default_factory=datetime.now)
    error: Optional[str] = None
    raw_response: Optional[Any] = None
    
    def to_json(self) -> str:
        """Serialize result to JSON"""
        return json.dumps({
            "success": self.success,
            "data": self.data,
            "source": self.source,
            "query": self.query,
            "timestamp": self.timestamp.isoformat(),
            "error": self.error
        }, indent=2)
    
    def to_dict(self) -> Dict:
        """Convert result to dictionary"""
        return {
            "success": self.success,
            "data": self.data,
            "source": self.source,
            "query": self.query,
            "timestamp": self.timestamp.isoformat(),
            "error": self.error
        }
    
    def summary(self) -> str:
        """Human-readable summary"""
        if not self.success:
            return f"[FAILED] {self.source}: {self.error}"
        
        data_keys = list(self.data.keys())
        preview = data_keys[:3] if data_keys else []
        return f"[SUCCESS] {self.source} | {self.query} | Fields: {', '.join(preview)}"


class RateLimiter:
    """Rate limiter to respect API limits"""
    
    def __init__(self, calls_per_second: float = 1.0):
        self.calls_per_second = calls_per_second
        self.min_interval = 1.0 / calls_per_second if calls_per_second > 0 else 0
        self.last_call = datetime.min
    
    def wait_if_needed(self):
        """Wait if we're making requests too quickly"""
        if self.calls_per_second <= 0:
            return
            
        elapsed = (datetime.now() - self.last_call).total_seconds()
        if elapsed < self.min_interval:
            import time
            time.sleep(self.min_interval - elapsed)
        self.last_call = datetime.now()


class MambaClient:
    """Main client for Mamba OSINT operations"""
    
    def __init__(self, api_keys: Dict[str, str] = None, rate_limit: float = 1.0):
        self.api_keys = api_keys or {}
        self.rate_limiter = RateLimiter(calls_per_second=rate_limit)
        self.session = None
        self._setup_session()
    
    def _setup_session(self):
        """Configure requests session with retries"""
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=20, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({
            "User-Agent": "Mamba-OSINT/1.0 (Security Research Tool)"
        })
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Retrieve API key for specific service"""
        return self.api_keys.get(service)
    
    def set_api_key(self, service: str, key: str):
        """Set API key for a service"""
        self.api_keys[service] = key
    
    def request(self, method: str, url: str, **kwargs) -> Optional[Dict]:
        """Make rate-limited HTTP request"""
        self.rate_limiter.wait_if_needed()
        try:
            response = self.session.request(method, url, timeout=30, **kwargs)
            response.raise_for_status()
            
            content_type = response.headers.get('content-type', '')
            if 'application/json' in content_type:
                return response.json()
            elif response.text:
                return {"text": response.text}
            return {}
            
        except requests.RequestException as e:
            return {"error": str(e), "status_code": getattr(e.response, 'status_code', None)}
    
    def close(self):
        """Close the session"""
        if self.session:
            self.session.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()