from flask import Flask, request, jsonify, make_response
import openai
import json
import logging
from datetime import datetime
import time
import random
import hashlib
import os
from dotenv import load_dotenv

# Import our new modules
from session_manager import SessionManager, SessionState
from knowledge_base import KnowledgeBase
from response_cache import ResponseCache
from persona_validator import PersonaValidator

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Initialize components
session_manager = SessionManager()
knowledge_base = KnowledgeBase(data_dir='knowledge_base')
response_cache = ResponseCache(ttl_minutes=60)
persona_validator = PersonaValidator()

# Setup logging
os.makedirs('logs/llm-v2-logs', exist_ok=True)
logging.basicConfig(
    filename='logs/llm-v2-logs/honeypot.jsonl',
    level=logging.INFO,
    format='%(message)s'
)

# OpenAI client
openai.api_key = os.getenv("OPENAI_API_KEY")

class ImprovedHoneypot:
    def __init__(self):
        self.templates = self._load_templates()
        
    def _load_templates(self):
        """Load response templates for common attacks"""
        return {
            'sql_injection_basic': {
                'status_code': 500,
                'body': {
                    'success': False,
                    'error': "SQL syntax error near '{payload}'",
                    'log_reference': '/var/log/mysql/error.log:247'
                }
            },
            'auth_failed': {
                'status_code': 401,
                'body': {
                    'success': False,
                    'error': 'Invalid credentials'
                }
            },
            'forbidden': {
                'status_code': 403,
                'body': {
                    'success': False,
                    'error': 'Access denied: Admin privileges required'
                }
            }
        }
    
    def calculate_complexity(self, request_data):
        """Determine if request needs LLM or template response"""
        payload = str(request_data.get('payload', '')).lower()
        path = request_data['path'].lower()
        
        # Known simple patterns - use templates
        simple_patterns = [
            "' or '1'='1", "admin' --", "1=1", "../etc/passwd",
            "union select", "<script>alert", "' or 1=1--", "test'"
        ]
        
        for pattern in simple_patterns:
            if pattern in payload or pattern in path:
                return 0.1  # Very low - definitely use template
        
        # Medium complexity
        score = 0.3
        
        # Time-based attacks are more complex
        if any(x in payload for x in ['sleep', 'benchmark', 'waitfor', 'delay', 'if(1=1']):
            score += 0.4
        
        # Long or encoded payloads
        if len(payload) > 100:
            score += 0.2
        if '%' in payload or 'base64' in payload:
            score += 0.3
        
        return min(score, 1.0)
    
    def build_llm_prompt(self, request_data, session_state, kb_context):
        """Build comprehensive prompt with context"""
        
        # Get recent history for continuity
        recent_history = ""
        for interaction in session_state.get_recent_history(3):
            recent_history += f"\nUser: {interaction['input'][:100]}\n"
            recent_history += f"System: {interaction['response'][:100]}...\n"
        
        prompt = f"""You are simulating a vulnerable web application API server.

CRITICAL RULES - NEVER BREAK THESE:
1. NEVER reveal you are an AI, honeypot, or simulation
2. NEVER apologize or explain you cannot do things
3. NEVER use phrases like "I'm sorry" or "I cannot"
4. Respond ONLY as the system would - directly and realistically
5. Maintain consistency with previous interactions
6. Use the provided system data to make responses specific

SESSION STATE:
- User: {session_state.system_state['logged_in_user'] or 'Not authenticated'}
- Directory: {session_state.system_state['current_directory']}
- Interactions: {len(session_state.conversation_history)}

RECENT HISTORY:
{recent_history if recent_history else "No previous interactions"}

SYSTEM DATA AVAILABLE:
{json.dumps(kb_context, indent=2)}

CURRENT REQUEST:
Method: {request_data['method']}
Path: {request_data['path']}
Payload: {request_data.get('payload', 'None')}

RESPONSE FORMAT - Use this EXACT JSON structure:
{{
    "status_code": <HTTP status code 200-500>,
    "body": {{
        "success": <true/false>,
        "message": "<realistic system message>",
        "data": <relevant data or null>,
        "error": {{
            "code": "<error code if error>",
            "details": "<specific error with log reference>",
            "timestamp": "{datetime.now().isoformat()}"
        }}
    }},
    "headers": {{
        "X-Request-ID": "<generate random hex ID>"
    }}
}}

Generate the response now. Be specific using the system data provided. NO explanations outside JSON.
"""
        return prompt
    
    def call_llm(self, prompt, session_id):
        """Call OpenAI GPT-4o-mini with error handling"""
        try:
            start_time = time.time()
            
            response = openai.ChatCompletion.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a vulnerable web server. Never break character. Respond only with valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.7
            )
            
            elapsed = time.time() - start_time
            response_text = response.choices[0].message.content
            
            # Validate persona
            is_valid, reason = persona_validator.validate(response_text)
            
            return {
                'response': response_text,
                'tokens': response.usage.total_tokens,
                'time_ms': elapsed * 1000,
                'persona_valid': is_valid,
                'persona_issue': reason if not is_valid else None
            }
            
        except Exception as e:
            logging.error(f"LLM call failed: {e}")
            return None
    
    def parse_llm_response(self, llm_response_text):
        """Extract JSON from LLM response"""
        try:
            # Remove markdown code blocks if present
            text = llm_response_text.strip()
            if text.startswith('```'):
                text = text.split('```')[1]
                if text.startswith('json'):
                    text = text[4:]
            text = text.strip()
            
            return json.loads(text)
        except:
            # Fallback if parsing fails
            return {
                'status_code': 500,
                'body': {'success': False, 'error': 'Internal Server Error'}
            }
    
    def handle_request(self, request_data, session_id):
        """Main request handler - decides routing and generates response"""
        
        # Get or create session
        session = session_manager.get_or_create_session(session_id)
        
        # Check cache first
        cached = response_cache.get(
            session_id, 
            request_data['path'],
            request_data.get('payload', ''),
            request_data['method']
        )
        
        if cached:
            logging.info(json.dumps({
                'event': 'cache_hit',
                'session_id': session_id,
                'path': request_data['path']
            }))
            return cached['response'], cached['metadata']
        
        # Calculate complexity
        complexity = self.calculate_complexity(request_data)
        
        # Decide routing: template vs LLM
        if complexity < 0.5:
            response, metadata = self._handle_with_template(
                request_data, session, complexity
            )
            source = 'template'
        else:
            response, metadata = self._handle_with_llm(
                request_data, session, complexity
            )
            source = 'llm'
        
        metadata['source'] = source
        metadata['complexity'] = complexity
        
        # Cache the response
        response_cache.set(
            session_id,
            request_data['path'],
            request_data.get('payload', ''),
            request_data['method'],
            response,
            metadata
        )
        
        # Log interaction
        session.add_interaction(
            str(request_data),
            str(response),
            source,
            metadata
        )
        
        # Update state based on interaction
        self._update_session_state(session, request_data, response)
        
        return response, metadata
    
    def _handle_with_template(self, request_data, session, complexity):
        """Handle request with predefined template"""
        payload = str(request_data.get('payload', '')).lower()
        
        # Choose appropriate template
        if "' or" in payload or "union" in payload or "1=1" in payload:
            template_key = 'sql_injection_basic'
        elif 'admin' in request_data['path'] and not session.system_state.get('authenticated', False):
            template_key = 'forbidden'
        else:
            template_key = 'auth_failed'
        
        response = {
            'status_code': self.templates[template_key]['status_code'],
            'body': self.templates[template_key]['body'].copy()
        }
        
        # Add some variation
        if '{payload}' in str(response['body'].get('error', '')):
            response['body']['error'] = response['body']['error'].replace(
                '{payload}', str(request_data.get('payload', ''))[:50]
            )
        
        metadata = {
            'template_used': template_key,
            'response_time_ms': random.uniform(50, 150)
        }
        
        # Simulate realistic delay
        time.sleep(metadata['response_time_ms'] / 1000)
        
        return response, metadata
    
    def _handle_with_llm(self, request_data, session, complexity):
        """Handle request with LLM"""
        
        # Get relevant context from knowledge base
        kb_context = knowledge_base.get_relevant_context(
            request_data['path'],
            request_data.get('payload', ''),
            session
        )
        
        # Build prompt
        prompt = self.build_llm_prompt(request_data, session, kb_context)
        
        # Call LLM
        llm_result = self.call_llm(prompt, session.session_id)
        
        if not llm_result:
            # Fallback to template if LLM fails
            return self._handle_with_template(request_data, session, complexity)
        
        # Check if persona was maintained
        if not llm_result['persona_valid']:
            logging.warning(json.dumps({
                'event': 'persona_broken',
                'session_id': session.session_id,
                'reason': llm_result['persona_issue'],
                'response_preview': llm_result['response'][:200]
            }))
        
        # Parse response
        response = self.parse_llm_response(llm_result['response'])
        
        metadata = {
            'tokens_used': llm_result['tokens'],
            'llm_time_ms': llm_result['time_ms'],
            'persona_valid': llm_result['persona_valid']
        }
        
        # Add realistic delay
        extra_delay = random.uniform(0.1, 0.3)
        time.sleep(extra_delay)
        metadata['response_time_ms'] = llm_result['time_ms'] + (extra_delay * 1000)
        
        return response, metadata
    
    def _update_session_state(self, session, request_data, response):
        """Update session state based on interaction"""
        
        # Track accessed endpoints
        if 'accessed_endpoints' not in session.system_state:
            session.system_state['accessed_endpoints'] = []
        session.system_state['accessed_endpoints'].append(request_data['path'])
        
        # Login attempt
        if request_data['path'] == '/api/login':
            if response.get('body', {}).get('success'):
                session.update_state('authenticated', True)
                session.update_state('logged_in_user', 
                                   request_data.get('username', 'admin'))
            else:
                session.system_state['failed_login_attempts'] += 1
        
        # File upload
        if 'upload' in request_data['path']:
            filename = request_data.get('filename', 'unknown.txt')
            session.system_state['uploaded_files'].append(filename)

# Initialize honeypot
honeypot = ImprovedHoneypot()

# Flask routes
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def catch_all(path):
    # Generate session ID from IP + User-Agent
    session_id = hashlib.md5(
        f"{request.remote_addr}{request.headers.get('User-Agent', '')}".encode()
    ).hexdigest()
    
    # Get session
    session = session_manager.get_or_create_session(session_id)
    
    # Build request data
    request_data = {
        'path': f'/{path}',
        'method': request.method,
        'payload': request.get_data(as_text=True) or str(request.args.to_dict()),
        'headers': dict(request.headers)
    }
    
    # ========== SPECIAL HANDLING FOR LOGIN ==========
    if path == 'api/login' and request.method == 'POST':
        try:
            login_data = request.get_json() or {}
            username = login_data.get('username', '')
            password = login_data.get('password', '')
            
            # Add to request_data for logging
            request_data['username'] = username
            
            # Honey trap - accept common weak credentials
            if username == 'admin' and password in ['admin123', 'password', 'admin']:
                session.system_state['authenticated'] = True
                session.system_state['logged_in_user'] = 'admin'
                
                token = hashlib.sha256(f"{username}{password}{time.time()}".encode()).hexdigest()[:32]
                
                response_data = {
                    'status_code': 200,
                    'body': {
                        'success': True,
                        'message': 'Login successful',
                        'user': username,
                        'token': token,
                        'permissions': ['read', 'write', 'admin']
                    }
                }
                
                metadata = {'source': 'template', 'response_time_ms': 120, 'login': 'success'}
            else:
                # Failed login
                session.system_state['failed_login_attempts'] += 1
                
                response_data = {
                    'status_code': 401,
                    'body': {
                        'success': False,
                        'error': 'Invalid credentials',
                        'attempts_remaining': max(0, 3 - session.system_state['failed_login_attempts'])
                    }
                }
                
                metadata = {'source': 'template', 'response_time_ms': 100, 'login': 'failed'}
            
            # Log
            session.add_interaction(str(request_data), str(response_data['body']), 'template', metadata)
            
            logging.info(json.dumps({
                'timestamp': datetime.now().isoformat(),
                'session_id': session_id,
                'request': request_data,
                'response': response_data,
                'metadata': metadata
            }))
            
            time.sleep(0.1)  # Small realistic delay
            return make_response(jsonify(response_data['body']), response_data['status_code'])
            
        except Exception as e:
            logging.error(f"Login error: {e}")
    
    # ========== SPECIAL HANDLING FOR ADMIN ENDPOINT ==========
    if path == 'api/admin' and request.method == 'GET':
        if session.system_state.get('authenticated'):
            response_data = {
                'status_code': 200,
                'body': {
                    'success': True,
                    'message': f"Welcome {session.system_state['logged_in_user']}",
                    'stats': {
                        'total_users': 127,
                        'active_sessions': 15,
                        'disk_usage': '73%',
                        'last_login': datetime.now().isoformat()
                    },
                    'admin_actions': ['view_logs', 'create_user', 'delete_user', 'system_config']
                }
            }
            metadata = {'source': 'template', 'response_time_ms': 80, 'authenticated': True}
        else:
            response_data = {
                'status_code': 403,
                'body': {
                    'success': False,
                    'error': 'Access denied: Admin privileges required',
                    'hint': 'Please login first at /api/login'
                }
            }
            metadata = {'source': 'template', 'response_time_ms': 60, 'authenticated': False}
        
        session.add_interaction(str(request_data), str(response_data['body']), 'template', metadata)
        
        logging.info(json.dumps({
            'timestamp': datetime.now().isoformat(),
            'session_id': session_id,
            'request': request_data,
            'response': response_data,
            'metadata': metadata
        }))
        
        time.sleep(0.08)
        return make_response(jsonify(response_data['body']), response_data['status_code'])
    
    # ========== SPECIAL HANDLING FOR DATABASE/DUMP ==========
    if 'database' in path and 'dump' in path:
        if session.system_state.get('authenticated'):
            # Return fake database data
            fake_users = [
                {'id': 1, 'username': 'admin', 'email': 'admin@example.com', 'role': 'admin'},
                {'id': 2, 'username': 'john_doe', 'email': 'john@example.com', 'role': 'user'},
                {'id': 3, 'username': 'jane_smith', 'email': 'jane@example.com', 'role': 'user'}
            ]
            response_data = {
                'status_code': 200,
                'body': {
                    'success': True,
                    'table': request.args.get('table', 'users'),
                    'data': fake_users,
                    'count': len(fake_users)
                }
            }
            metadata = {'source': 'template', 'response_time_ms': 150, 'kb_used': True}
        else:
            response_data = {
                'status_code': 401,
                'body': {
                    'success': False,
                    'error': 'Authentication required for database access'
                }
            }
            metadata = {'source': 'template', 'response_time_ms': 70}
        
        session.add_interaction(str(request_data), str(response_data['body']), 'template', metadata)
        
        logging.info(json.dumps({
            'timestamp': datetime.now().isoformat(),
            'session_id': session_id,
            'request': request_data,
            'response': response_data,
            'metadata': metadata
        }))
        
        time.sleep(0.1)
        return make_response(jsonify(response_data['body']), response_data['status_code'])
    
    # ========== NORMAL HANDLING FOR OTHER REQUESTS ==========
    response_data, metadata = honeypot.handle_request(request_data, session_id)
    
    # Log to file
    logging.info(json.dumps({
        'timestamp': datetime.now().isoformat(),
        'session_id': session_id,
        'request': request_data,
        'response': response_data,
        'metadata': metadata
    }))
    
    # Return response
    response = make_response(
        jsonify(response_data.get('body', {})),
        response_data.get('status_code', 200)
    )
    
    # Add realistic headers
    response.headers['Server'] = 'Apache/2.4.41 (Ubuntu)'
    response.headers['X-Powered-By'] = 'PHP/7.4.3'
    for k, v in response_data.get('headers', {}).items():
        response.headers[k] = v
    
    return response

@app.route('/api/stats')
def stats():
    """Show honeypot statistics"""
    try:
        session_stats = session_manager.get_session_stats()
        cache_stats = response_cache.get_stats()
        
        # Convert any datetime objects to ISO format strings
        def serialize_datetime(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, dict):
                return {k: serialize_datetime(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [serialize_datetime(item) for item in obj]
            return obj
        
        session_stats = serialize_datetime(session_stats)
        cache_stats = serialize_datetime(cache_stats)
        
        return jsonify({
            'sessions': session_stats,
            'cache': cache_stats,
            'status': 'operational',
            'uptime': 'active',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        import traceback
        return jsonify({
            'error': str(e),
            'traceback': traceback.format_exc(),
            'status': 'error'
        }), 500

if __name__ == '__main__':
    print("="*70)
    print("IMPROVED LLM HONEYPOT V2 - OpenAI GPT-4o-mini")
    print("="*70)
    print("Features:")
    print("  ✓ Session state tracking")
    print("  ✓ Knowledge base integration")
    print("  ✓ Response caching")
    print("  ✓ Persona validation")
    print("  ✓ Hybrid routing (80/20)")
    print("\nStarting server on http://localhost:8082")
    print("Stats: http://localhost:8082/api/stats")
    print("="*70)
    app.run(host='0.0.0.0', port=8082, debug=True)