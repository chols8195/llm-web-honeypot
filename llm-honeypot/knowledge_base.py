"""
Knowledge Base for Realistic Honeypot Responses
Provides fake but believable system data
"""
import json
import random
from typing import Dict, Any

class KnowledgeBase:
    """Manages fake data to make responses realistic"""
    
    def __init__(self, data_dir: str = 'data'):
        self.data_dir = data_dir
        self.fake_users = self._load_json('fake_db_dumps.json')
        self.fake_logs = self._load_json('fake_logs.json')
        self.fake_configs = self._load_json('fake_configs.json')
        self.fake_errors = self._load_json('fake_errors.json')
        
    def _load_json(self, filename: str) -> Any:
        """Load JSON data file"""
        try:
            with open(f'{self.data_dir}/{filename}', 'r') as f:
                return json.load(f)
        except:
            return []
    
    def get_relevant_context(self, request_path: str, payload: str, 
                            session_state: Any) -> Dict[str, Any]:
        """
        Get relevant fake data based on request type
        This is KEY to believability - research showed this makes huge difference
        """
        context = {}
        payload_lower = payload.lower()
        path_lower = request_path.lower()
        
        # SQL injection attempts - provide fake database info
        if any(x in payload_lower for x in ['select', 'union', 'sql', 'database']):
            context['database'] = {
                'type': 'MySQL 8.0.32',
                'current_db': 'api_production',
                'tables': ['users', 'posts', 'sessions', 'api_keys'],
                'sample_users': self.fake_users[0]['sample_data'] if self.fake_users else []
            }
            context['sql_error_template'] = random.choice(
                self.fake_errors[0]['variants'] if self.fake_errors else ['SQL error']
            )
        
        # File access attempts - provide fake file system
        if any(x in payload_lower or x in path_lower 
               for x in ['file', '..', 'etc', 'passwd', 'config']):
            context['filesystem'] = {
                'configs': self.fake_configs,
                'current_path': session_state.system_state['current_directory']
            }
        
        # Admin/auth requests - provide fake user context
        if any(x in path_lower for x in ['admin', 'login', 'auth', 'user']):
            context['auth_info'] = {
                'current_user': session_state.system_state['logged_in_user'],
                'failed_attempts': session_state.system_state['failed_login_attempts'],
                'session_valid': session_state.system_state['authenticated']
            }
        
        # Log access - provide fake logs
        if 'log' in path_lower or 'log' in payload_lower:
            context['recent_logs'] = random.sample(
                self.fake_logs, min(3, len(self.fake_logs))
            ) if self.fake_logs else []
        
        return context
    
    def get_error_message(self, error_type: str) -> str:
        """Get realistic error message"""
        for error in self.fake_errors:
            if error['code'].lower() == error_type.lower():
                return random.choice(error['variants'])
        return "Internal Server Error"