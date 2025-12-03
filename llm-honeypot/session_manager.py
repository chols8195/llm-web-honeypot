"""
Session Management for LLM Honeypot
Tracks state across multiple attacker interactions
"""
import json
from datetime import datetime
from typing import Dict, List, Any

class SessionState:
    """Maintains state for a single attacker session"""
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.conversation_history = []
        self.system_state = {
            'current_directory': '/home/admin',
            'logged_in_user': None,
            'authenticated': False,
            'created_files': [],
            'uploaded_files': [],
            'accessed_endpoints': [],
            'failed_login_attempts': 0
        }
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        
    def add_interaction(self, user_input: str, system_response: str, 
                       response_type: str, metadata: Dict):
        """Record an interaction with full context"""
        self.conversation_history.append({
            'timestamp': datetime.now().isoformat(),
            'input': user_input,
            'response': system_response,
            'type': response_type,  # 'template', 'llm', 'cached'
            'metadata': metadata,
            'state_before': self.system_state.copy()
        })
        self.last_activity = datetime.now()
        
    def get_recent_history(self, n: int = 5) -> List[Dict]:
        """Get last N interactions for LLM context"""
        return self.conversation_history[-n:] if self.conversation_history else []
    
    def update_state(self, key: str, value: Any):
        """Update system state"""
        self.system_state[key] = value
        
    def get_state_summary(self) -> str:
        """Get human-readable state summary for LLM prompt"""
        return f"""
Current Session State:
- User: {self.system_state['logged_in_user'] or 'Not authenticated'}
- Directory: {self.system_state['current_directory']}
- Files created: {len(self.system_state['created_files'])}
- Interactions: {len(self.conversation_history)}
- Session duration: {(datetime.now() - self.created_at).seconds}s
"""

class SessionManager:
    """Manages all active sessions"""
    
    def __init__(self):
        self.sessions = {}
        
    def get_or_create_session(self, session_id: str) -> SessionState:
        """Get existing session or create new one"""
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionState(session_id)
        return self.sessions[session_id]
    
    def get_session_stats(self) -> Dict:
        """Get statistics across all sessions"""
        return {
            'total_sessions': len(self.sessions),
            'active_sessions': sum(1 for s in self.sessions.values() 
                                  if (datetime.now() - s.last_activity).seconds < 300),
            'total_interactions': sum(len(s.conversation_history) 
                                     for s in self.sessions.values())
        }