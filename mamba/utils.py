"""
Utility functions for data processing, caching, and formatting
"""

import json
import csv
import io
from typing import List, Dict, Any, Optional
from datetime import datetime
from .core import OSINTResult


class CacheManager:
    """In-memory cache for OSINT results"""
    
    def __init__(self, ttl_seconds: int = 300, max_size: int = 1000):
        self.cache = {}
        self.ttl = ttl_seconds
        self.max_size = max_size
    
    def get(self, key: str) -> Optional[Dict]:
        """Get item from cache if not expired"""
        if key in self.cache:
            data, timestamp = self.cache[key]
            if (datetime.now() - timestamp).total_seconds() < self.ttl:
                return data
            else:
                del self.cache[key]
        return None
    
    def set(self, key: str, value: Dict):
        """Store item in cache"""
        if len(self.cache) >= self.max_size:
            self._remove_oldest()
        self.cache[key] = (value, datetime.now())
    
    def _remove_oldest(self):
        """Remove oldest cache entry"""
        if self.cache:
            oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k][1])
            del self.cache[oldest_key]
    
    def clear(self):
        """Clear entire cache"""
        self.cache.clear()
    
    def stats(self) -> Dict:
        """Get cache statistics"""
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "ttl_seconds": self.ttl
        }


class ResultFormatter:
    """Format OSINT results in various output formats"""
    
    @staticmethod
    def to_json(results: List[OSINTResult], pretty: bool = True) -> str:
        """Convert results to JSON"""
        data = [r.to_dict() for r in results]
        if pretty:
            return json.dumps(data, indent=2)
        return json.dumps(data)
    
    @staticmethod
    def to_csv(results: List[OSINTResult]) -> str:
        """Convert results to CSV format"""
        output = io.StringIO()
        fieldnames = ["query", "source", "success", "timestamp", "error"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for r in results:
            writer.writerow({
                "query": r.query,
                "source": r.source,
                "success": r.success,
                "timestamp": r.timestamp.isoformat(),
                "error": r.error or ""
            })
        
        return output.getvalue()
    
    @staticmethod
    def to_table(results: List[OSINTResult]) -> str:
        """Format results as ASCII table"""
        if not results:
            return "No results"
        
        lines = []
        lines.append("=" * 80)
        lines.append(f"MAMBA OSINT REPORT - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 80)
        
        for i, r in enumerate(results, 1):
            lines.append(f"\n[{i}] {r.source} | Query: {r.query}")
            lines.append(f"    Success: {'Yes' if r.success else 'No'}")
            
            if r.error:
                lines.append(f"    Error: {r.error[:100]}")
            
            if r.data:
                lines.append("    Data:")
                for key, value in list(r.data.items())[:5]:
                    value_str = str(value)[:60]
                    lines.append(f"      - {key}: {value_str}")
        
        return "\n".join(lines)


class BatchProcessor:
    """Process multiple queries in batch mode"""
    
    def __init__(self, client, cache_manager: Optional[CacheManager] = None):
        self.client = client
        self.cache = cache_manager or CacheManager()
        self.stats = {"total": 0, "cached": 0, "fresh": 0}
    
    def process_emails(self, emails: List[str], check_breach: bool = False) -> List[OSINTResult]:
        """Batch process email addresses"""
        from .modules import EmailReputation
        email_module = EmailReputation(self.client)
        results = []
        
        for email in emails:
            self.stats["total"] += 1
            cache_key = f"email_{email}"
            cached = self.cache.get(cache_key)
            
            if cached:
                self.stats["cached"] += 1
                results.append(OSINTResult(**cached))
            else:
                self.stats["fresh"] += 1
                result = email_module.validate_format(email)
                self.cache.set(cache_key, result.to_dict())
                results.append(result)
        
        return results
    
    def get_stats(self) -> Dict:
        """Get batch processing statistics"""
        return {
            **self.stats,
            "cache_hit_rate": f"{(self.stats['cached']/self.stats['total']*100):.1f}%" if self.stats['total'] > 0 else "0%"
        }