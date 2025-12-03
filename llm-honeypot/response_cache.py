"""
Response Caching for Consistency
Ensures identical requests get identical responses
"""
import hashlib
import json
from datetime import datetime, timedelta
from typing import Optional, Dict

class ResponseCache:
    """
    Cache LLM responses for consistency
    Research showed this is critical: same input = same output
    """
    
    def __init__(self, ttl_minutes: int = 60):
        self.cache = {}
        self.ttl = timedelta(minutes=ttl_minutes)
        
    def _make_key(self, session_id: str, request_path: str, 
                  payload: str, method: str) -> str:
        """Create deterministic cache key"""
        key_string = f"{session_id}:{method}:{request_path}:{payload}"
        return hashlib.sha256(key_string.encode()).hexdigest()
    
    def get(self, session_id: str, request_path: str, 
            payload: str, method: str) -> Optional[Dict]:
        """Retrieve cached response if exists and not expired"""
        key = self._make_key(session_id, request_path, payload, method)
        
        if key in self.cache:
            cached = self.cache[key]
            age = datetime.now() - cached['timestamp']
            
            if age < self.ttl:
                cached['metadata']['cache_hit'] = True
                return cached
            else:
                # Expired - remove it
                del self.cache[key]
        
        return None
    
    def set(self, session_id: str, request_path: str, payload: str, 
            method: str, response: Dict, metadata: Dict):
        """Store response in cache"""
        key = self._make_key(session_id, request_path, payload, method)
        self.cache[key] = {
            'response': response,
            'metadata': metadata,
            'timestamp': datetime.now()
        }
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        return {
            'total_cached': len(self.cache),
            'memory_kb': len(json.dumps(self.cache)) / 1024
        }