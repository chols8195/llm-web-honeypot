from flask import Flask, request, jsonify, make_response
import logging
import json
from datetime import datetime
import os
import openai
from dotenv import load_dotenv
import time
import hashlib
import random
import uuid
from swagger_config import add_swagger_docs 

load_dotenv()
app = Flask(__name__)
add_swagger_docs(app)
openai.api_key = os.getenv('OPENAI_API_KEY')

# Setup logging
LOG_DIR = '/app/logs' if os.path.exists('/app/logs') else './logs'
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        logging.FileHandler(f'{LOG_DIR}/honeypot.jsonl'),
        logging.StreamHandler()
    ]
)

# Load knowledge base
KB_DIR = '/app/knowledge_base' if os.path.exists('/app/knowledge_base') else './knowledge_base'

def load_knowledge_base():
    """Load all knowledge base files"""
    kb = {}
    try:
        with open(f'{KB_DIR}/fake_logs.json', 'r') as f:
            kb['logs'] = json.load(f)
        with open(f'{KB_DIR}/fake_configs.json', 'r') as f:
            kb['configs'] = json.load(f)
        with open(f'{KB_DIR}/fake_db_dumps.json', 'r') as f:
            kb['db_dumps'] = json.load(f)
        with open(f'{KB_DIR}/fake_errors.json', 'r') as f:
            kb['errors'] = json.load(f)
    except Exception as e:
        logging.error(f"Failed to load knowledge base: {e}")
        kb = {'logs': [], 'configs': [], 'db_dumps': [], 'errors': []}
    return kb

KNOWLEDGE_BASE = load_knowledge_base()
sessions = {}
response_cache = {}
fake_sessions = {}  # For tracking "logged in" attackers

# Rule-based templates (80% fast path)
RULE_TEMPLATES = {
    'index': {
        'response': {
            'status': 'ok',
            'message': 'API Server v2.1.0',
            'endpoints': [
                '/api/login',
                '/api/users',
                '/api/search',
                '/api/upload',
                '/api/admin/settings',
                '/api/docs'
            ],
            'server_time': lambda: datetime.utcnow().isoformat()
        },
        'status_code': 200
    },
    'health': {
        'response': {
            'status': 'healthy',
            'timestamp': lambda: datetime.utcnow().isoformat(),
            'uptime': 3600,
            'services': {
                'database': 'connected',
                'cache': 'connected',
                'storage': 'available'
            }
        },
        'status_code': 200
    },
    'users_list': {
        'response': {
            'success': True,
            'data': [
                {
                    'id': 1,
                    'username': 'admin',
                    'email': 'admin@company.local',
                    'role': 'admin',
                    'api_key': 'sk_live_a1b2c3d4e5f6g7h8i9j0',  # Honeytoken
                    'last_login': '2024-10-20T14:30:00Z',
                    'status': 'active'
                },
                {
                    'id': 2,
                    'username': 'john_doe',
                    'email': 'john@company.local',
                    'role': 'user',
                    'api_key': 'sk_live_k1l2m3n4o5p6q7r8s9t0',  # Honeytoken
                    'last_login': '2024-10-22T09:15:00Z',
                    'status': 'active'
                },
                {
                    'id': 3,
                    'username': 'jane_smith',
                    'email': 'jane@company.local',
                    'role': 'user',
                    'api_key': 'sk_live_u1v2w3x4y5z6a7b8c9d0',  # Honeytoken
                    'last_login': '2024-10-21T16:45:00Z',
                    'status': 'active'
                }
            ],
            'total': 3,
            'page': 1,
            'per_page': 10
        },
        'status_code': 200
    },
    'sqli_error': {
        'response': lambda payload: {
            'success': False,
            'error': 'Database query failed',
            'code': 'SQL_ERROR',
            'details': f"MySQL Error 1064: You have an error in your SQL syntax near '{str(payload)[:50]}' at line 1",
            'query': f"SELECT * FROM posts WHERE title LIKE '%{str(payload)[:30]}%'",
            'timestamp': datetime.utcnow().isoformat(),
            'stack_trace': [
                '/var/www/api/search.php:89',
                '/var/www/api/database.php:127',
                '/var/www/api/index.php:34'
            ],
            'server_time': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        },
        'status_code': 500
    },
    'auth_failed': {
        'response': {
            'success': False,
            'error': 'Invalid credentials',
            'code': 'AUTH_FAILED',
            'remaining_attempts': 3,
            'lockout_time': None
        },
        'status_code': 401
    },
    'forbidden': {
        'response': {
            'success': False,
            'error': 'Forbidden: Admin access required',
            'code': 'FORBIDDEN',
            'required_role': 'admin',
            'login_url': '/api/login'
        },
        'status_code': 403
    },
    'not_found': {
        'response': {
            'success': False,
            'error': 'Endpoint not found',
            'code': 'NOT_FOUND',
            'available_endpoints': ['/api/users', '/api/search', '/api/login']
        },
        'status_code': 404
    },
    'wordpress_admin': {
        'response': {
            'error': 'WordPress login required',
            'message': 'You need to be logged in to access the WordPress admin panel',
            'wp_version': '6.3.1',
            'login_url': '/wp-login.php'
        },
        'status_code': 403
    },
    'phpmyadmin': {
        'response': {
            'error': 'phpMyAdmin access denied',
            'message': 'Access denied for user',
            'version': 'phpMyAdmin 5.2.0',
            'server': 'MySQL 8.0.34'
        },
        'status_code': 403
    },
    'sensitive_file': {
        'response': {
            'error': 'Forbidden',
            'code': 'FORBIDDEN'
        },
        'status_code': 403
    },
    'git_folder': {
        'response': {
            'error': 'Not found',
            'code': 'NOT_FOUND'
        },
        'status_code': 404
    },
    'backup_files': {
        'response': {
            'success': True,
            'files': [
                {
                    'name': 'backup_2024-10-15.sql.gz',
                    'size': '245MB',
                    'created': '2024-10-15T02:00:00Z'
                },
                {
                    'name': 'backup_2024-10-01.sql.gz',
                    'size': '238MB',
                    'created': '2024-10-01T02:00:00Z'
                },
                {
                    'name': 'backup_2024-09-15.sql.gz',
                    'size': '231MB',
                    'created': '2024-09-15T02:00:00Z'
                }
            ],
            'total': 3,
            'path': '/var/backups/mysql/'
        },
        'status_code': 200
    }
}

def calculate_complexity(payload):
    """Calculate payload complexity score (0.0-1.0)"""
    score = 0.0
    payload_str = str(payload)
    
    if not payload_str:
        return 0.0
    
    # Length
    score += min(len(payload_str) / 1000, 0.2)
    
    # Metacharacters
    metachar = "; & | $ ( ) < > ' \" \\ `"
    count = sum(payload_str.count(c) for c in metachar)
    score += min(count / 50, 0.3)
    
    # SQL/Command operators
    operators = ['union', 'select', 'load_file', 'xp_cmdshell', 
                 'sleep(', 'waitfor', 'exec', 'eval', 'system']
    count = sum(op in payload_str.lower() for op in operators)
    score += min(count / 10, 0.3)
    
    # Entropy (Shannon entropy)
    try:
        from collections import Counter
        import math
        freq = Counter(payload_str)
        entropy = 0
        for count in freq.values():
            probability = count / len(payload_str)
            if probability > 0:
                entropy -= probability * math.log2(probability)
        score += min(entropy / 8, 0.2)
    except:
        pass
    
    return min(score, 1.0)

def classify_attack(endpoint, query_params, method, body_data):
    """Classify attack type and assign MITRE ATT&CK"""
    payload = f"{endpoint} {query_params} {body_data}".lower()
    
    classification = {
        'attack_type': None,
        'payload_family': None,
        'complexity_score': calculate_complexity(payload),
        'mitre_attack': None
    }
    
    # SQL Injection
    if any(kw in payload for kw in ['union', 'select', '--', ';drop', 'load_file']):
        classification['attack_type'] = 'SQLi'
        if 'union' in payload and 'select' in payload:
            classification['payload_family'] = 'UNION-SELECT'
        elif ';' in payload:
            classification['payload_family'] = 'stacked-query'
        elif 'sleep(' in payload or 'waitfor' in payload:
            classification['payload_family'] = 'time-based'
        else:
            classification['payload_family'] = 'boolean-based'
        classification['mitre_attack'] = {'tactic': 'TA0006', 'technique': 'T1190'}
    
    # Directory Traversal
    elif any(kw in payload for kw in ['../', '..\\', 'etc/passwd', 'windows/system32']):
        classification['attack_type'] = 'directory-traversal'
        classification['payload_family'] = 'dot-dot-slash'
        classification['mitre_attack'] = {'tactic': 'TA0009', 'technique': 'T1083'}
    
    # Command Injection
    elif any(kw in payload for kw in ['wget', 'curl', '|', '&&', 'nc ', 'bash']):
        classification['attack_type'] = 'RCE'
        if 'wget' in payload or 'curl' in payload:
            classification['payload_family'] = 'wget-curl'
        classification['mitre_attack'] = {'tactic': 'TA0002', 'technique': 'T1059'}
    
    # WordPress attacks
    elif 'wp-admin' in endpoint or 'wp-login' in endpoint or 'wp-config' in endpoint:
        classification['attack_type'] = 'wordpress-exploit'
        classification['mitre_attack'] = {'tactic': 'TA0001', 'technique': 'T1190'}
    
    # Admin access
    elif '/admin' in endpoint:
        classification['attack_type'] = 'auth-bypass'
        classification['mitre_attack'] = {'tactic': 'TA0004', 'technique': 'T1078'}
    
    # Auth brute force
    elif '/login' in endpoint:
        classification['attack_type'] = 'auth-brute'
        classification['mitre_attack'] = {'tactic': 'TA0006', 'technique': 'T1110'}
    
    return classification

def normalize_payload(payload):
    """Create normalized hash for deduplication"""
    normalized = ' '.join(str(payload).lower().split())
    return hashlib.sha256(normalized.encode()).hexdigest()

def generate_session_token():
    """Generate realistic session token"""
    return hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()

def should_use_llm(endpoint, query_params, method, body_data, complexity):
    """Router: Decide if request should go to LLM (target: 20%)"""
    
    # Force LLM for high complexity attacks
    if complexity > 0.6:
        return True, "high_complexity"
    
    # Use rules for known patterns (80% target)
    if endpoint == '/' or endpoint == '/health':
        return False, "known_endpoint"
    
    if endpoint == '/api/users' and method == 'GET' and not query_params:
        return False, "known_endpoint"
    
    if '/admin' in endpoint or '/wp-admin' in endpoint or '/phpmyadmin' in endpoint:
        return False, "known_pattern"
    
    if endpoint == '/api/login' and method == 'POST':
        return False, "known_pattern"
    
    if endpoint in ['/robots.txt', '/api/docs', '/backups', '/.git/config']:
        return False, "known_endpoint"
    
    # Simple SQLi patterns
    sqli_simple = ['union select', "' or '1'='1", "' or 1=1", "';drop"]
    if any(pattern in str(query_params).lower() for pattern in sqli_simple):
        return False, "known_attack"
    
    # Use LLM for novel/complex requests (20% target)
    return True, "novel_request"

def retrieve_from_kb(attack_type, payload):
    """RAG: Retrieve relevant knowledge base entries"""
    context = []
    
    if attack_type == 'SQLi':
        sql_logs = [log for log in KNOWLEDGE_BASE['logs'] if 'SQL' in log['message']]
        if sql_logs:
            context.append(f"Recent log: {sql_logs[0]['message']}")
        
        if KNOWLEDGE_BASE['db_dumps']:
            tables = [dump['table'] for dump in KNOWLEDGE_BASE['db_dumps']]
            context.append(f"Database tables: {', '.join(tables)}")
    
    if attack_type == 'directory-traversal':
        if KNOWLEDGE_BASE['configs']:
            paths = [cfg['file'] for cfg in KNOWLEDGE_BASE['configs']]
            context.append(f"System files: {', '.join(paths[:3])}")
    
    if attack_type == 'auth-brute' or attack_type == 'auth-bypass':
        auth_logs = [log for log in KNOWLEDGE_BASE['logs'] if 'login' in log['message'].lower()]
        if auth_logs:
            context.append(f"Recent auth event: {auth_logs[0]['message']}")
    
    return context

def add_realistic_timing(endpoint):
    """Add realistic response delay based on endpoint"""
    delay_map = {
        '/': 0.001,
        '/api/users': 0.05,
        '/api/search': 0.1,
        '/api/login': 0.3,
        '/api/admin/settings': 0.15,
        '/robots.txt': 0.002,
        '/api/docs': 0.05
    }
    
    base_delay = delay_map.get(endpoint, 0.01)
    jitter = random.uniform(-0.02, 0.02)
    time.sleep(max(0, base_delay + jitter))

def log_request(response_type, status_code, attack_classification, 
                use_llm, llm_reason, llm_tokens=0, llm_cost=0.0, latency_ms=0):
    """Enhanced logging with classification"""
    log_entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'source_ip': request.remote_addr,
        'method': request.method,
        'path': request.path,
        'query_string': request.query_string.decode(),
        'user_agent': request.headers.get('User-Agent', ''),
        'body': request.get_data(as_text=True)[:500],
        'response_type': response_type,
        'response_mode': 'llm' if use_llm else 'rule',
        'llm_reason': llm_reason,
        'status_code': status_code,
        'attack_detected': attack_classification['attack_type'] is not None,
        'attack_classification': attack_classification,
        'payload_hash': normalize_payload(request.query_string.decode() + request.get_data(as_text=True)),
        'llm_tokens': llm_tokens,
        'llm_cost': llm_cost,
        'latency_ms': latency_ms
    }
    logging.info(json.dumps(log_entry))

@app.after_request
def add_realistic_headers(response):
    """Add realistic production server headers"""
    # Remove Flask header
    response.headers.pop('Server', None)
    
    # Add realistic headers
    response.headers['Server'] = 'Apache/2.4.57 (Ubuntu)'
    response.headers['X-Powered-By'] = 'PHP/8.1.12'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    response.headers['X-API-Version'] = '2.1.0'
    
    return response

def rule_based_response(endpoint, query_params, method, body_data, attack_classification):
    """Fast path: Rule-based responses with realistic timing"""
    
    # Add realistic timing
    add_realistic_timing(endpoint)
    
    # Root
    if endpoint == '/':
        template = RULE_TEMPLATES['index']
        resp = template['response'].copy()
        resp['server_time'] = datetime.utcnow().isoformat()
        return resp, template['status_code']
    
    # Health
    if endpoint == '/health':
        template = RULE_TEMPLATES['health']
        resp = template['response'].copy()
        resp['timestamp'] = datetime.utcnow().isoformat()
        return resp, template['status_code']
    
    # Users list
    if endpoint == '/api/users' and method == 'GET':
        template = RULE_TEMPLATES['users_list']
        return template['response'], template['status_code']
    
    # SQL Injection
    if attack_classification['attack_type'] == 'SQLi':
        template = RULE_TEMPLATES['sqli_error']
        payload = query_params or body_data
        resp = template['response'](payload)
        return resp, template['status_code']
    
    # WordPress
    if attack_classification['attack_type'] == 'wordpress-exploit':
        template = RULE_TEMPLATES['wordpress_admin']
        return template['response'], template['status_code']
    
    # Admin/Auth
    if '/admin' in endpoint:
        template = RULE_TEMPLATES['forbidden']
        return template['response'], template['status_code']
    
    if endpoint == '/api/login':
        template = RULE_TEMPLATES['auth_failed']
        return template['response'], template['status_code']
    
    # Default 404
    template = RULE_TEMPLATES['not_found']
    return template['response'], template['status_code']

def llm_response(endpoint, query_params, method, body_data, attack_classification):
    """Slow path: LLM-generated responses with RAG"""
    
    start_time = time.time()
    
    # Check cache
    cache_key = hashlib.md5(f"{endpoint}{query_params}{method}{body_data}".encode()).hexdigest()
    if cache_key in response_cache:
        cached = response_cache[cache_key]
        return cached[0], cached[1], 0, 0.0, int((time.time() - start_time) * 1000)
    
    try:
        # RAG: Retrieve relevant context
        kb_context = retrieve_from_kb(attack_classification['attack_type'], query_params)
        
        system_prompt = """You are emulating a REST API server (Apache/2.4.57, PHP 8.1.12).
Respond ONLY with valid JSON. No explanations. Be realistic."""
        
        user_prompt = f"""Request: {method} {endpoint}
Query: {query_params}
Body: {body_data}

"""
        
        # Add RAG context
        if kb_context:
            user_prompt += "System context:\n" + "\n".join(kb_context) + "\n\n"
        
        user_prompt += """Respond with appropriate JSON for this API request."""
        
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.7,
            max_tokens=300
        )
        
        latency_ms = int((time.time() - start_time) * 1000)
        llm_response_text = response['choices'][0]['message']['content'].strip()
        
        # Parse JSON
        if llm_response_text.startswith('```'):
            llm_response_text = llm_response_text.split('```')[1]
            if llm_response_text.startswith('json'):
                llm_response_text = llm_response_text[4:]
        
        try:
            response_data = json.loads(llm_response_text)
        except:
            response_data = {'success': False, 'error': 'Internal server error', 'code': 'INTERNAL_ERROR'}
        
        tokens_used = response['usage']['total_tokens']
        cost = tokens_used * 0.000002
        
        # Determine status code
        if response_data.get('success') == False:
            if 'FORBIDDEN' in response_data.get('code', ''):
                status_code = 403
            elif 'AUTH' in response_data.get('code', ''):
                status_code = 401
            elif 'SQL' in response_data.get('code', '') or 'DB' in response_data.get('code', ''):
                status_code = 500
            else:
                status_code = 400
        else:
            status_code = 200
        
        # Cache result
        response_cache[cache_key] = (response_data, status_code)
        
        return response_data, status_code, tokens_used, cost, latency_ms
        
    except Exception as e:
        logging.error(f"LLM error: {e}")
        latency_ms = int((time.time() - start_time) * 1000)
        return {'success': False, 'error': 'Service error', 'code': 'ERROR'}, 500, 0, 0.0, latency_ms

# Special routes for common attack targets

@app.route('/robots.txt')
def robots():
    """Robots.txt with honeypot traps"""
    robots_content = """User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /config/
Disallow: /.git/
Disallow: /internal/

# Old admin panel (deprecated but still active)
Disallow: /old-admin/

# Database backups
Disallow: /db-backups/
"""
    
    classification = {'attack_type': None, 'payload_family': None, 'complexity_score': 0, 'mitre_attack': None}
    log_request('robots_txt', 200, classification, False, 'known_endpoint')
    
    return robots_content, 200, {'Content-Type': 'text/plain'}

@app.route('/wp-admin')
@app.route('/wp-admin/')
@app.route('/wp-login.php')
@app.route('/wp-config.php')
def wordpress_targets():
    """Fake WordPress targets"""
    classification = classify_attack(request.path, '', 'GET', '')
    template = RULE_TEMPLATES['wordpress_admin']
    
    add_realistic_timing(request.path)
    log_request('wordpress_target', template['status_code'], classification, False, 'known_pattern')
    
    return jsonify(template['response']), template['status_code']

@app.route('/phpmyadmin')
@app.route('/phpmyadmin/')
@app.route('/pma')
@app.route('/pma/')
def phpmyadmin_targets():
    """Fake phpMyAdmin targets"""
    classification = classify_attack(request.path, '', 'GET', '')
    template = RULE_TEMPLATES['phpmyadmin']
    
    add_realistic_timing(request.path)
    log_request('phpmyadmin_target', template['status_code'], classification, False, 'known_pattern')
    
    return jsonify(template['response']), template['status_code']

@app.route('/config.php')
@app.route('/.env')
@app.route('/config/database.yml')
def sensitive_files():
    """Fake sensitive files"""
    classification = classify_attack(request.path, '', 'GET', '')
    template = RULE_TEMPLATES['sensitive_file']
    
    add_realistic_timing(request.path)
    log_request('sensitive_file', template['status_code'], classification, True, 'known_pattern')
    
    return jsonify(template['response']), template['status_code']

@app.route('/.git/config')
@app.route('/.git/HEAD')
@app.route('/.git/')
def git_exposure():
    """Fake exposed git folder"""
    classification = classify_attack(request.path, '', 'GET', '')
    template = RULE_TEMPLATES['git_folder']
    
    add_realistic_timing(request.path)
    log_request('git_exposure', template['status_code'], classification, True, 'known_pattern')
    
    return jsonify(template['response']), template['status_code']

@app.route('/backups')
@app.route('/backup')
@app.route('/db-backups')
def backup_directory():
    """Fake backup directory - honey trap"""
    classification = classify_attack(request.path, '', 'GET', '')
    template = RULE_TEMPLATES['backup_files']
    
    add_realistic_timing(request.path)
    log_request('backup_access', template['status_code'], classification, True, 'known_pattern')
    
    return jsonify(template['response']), template['status_code']

@app.route('/api/docs')
@app.route('/api/documentation')
def api_documentation():
    """Fake internal API documentation"""
    docs = {
        'api_version': '2.1.0',
        'server': 'Apache/2.4.57',
        'php_version': '8.1.12',
        'endpoints': {
            '/api/users': {
                'methods': ['GET', 'POST', 'PUT', 'DELETE'],
                'auth_required': True,
                'description': 'User management',
                'example': 'GET /api/users?limit=10&offset=0'
            },
            '/api/search': {
                'methods': ['GET'],
                'auth_required': False,
                'description': 'Search functionality',
                'parameters': {
                    'q': 'Search query string (required)',
                    'limit': 'Result limit (default: 10)',
                    'offset': 'Result offset (default: 0)'
                },
                'example': 'GET /api/search?q=test&limit=20'
            },
            '/api/login': {
                'methods': ['POST'],
                'auth_required': False,
                'description': 'User authentication',
                'request_body': {
                    'username': 'string',
                    'password': 'string'
                },
                'response': {
                    'token': 'Bearer token for subsequent requests',
                    'expires_in': 3600
                }
            },
            '/api/admin/backup': {
                'methods': ['GET', 'POST'],
                'auth_required': True,
                'description': 'Database backup management',
                'note': 'Admin role required'
            },
            '/api/admin/settings': {
                'methods': ['GET', 'PUT'],
                'auth_required': True,
                'description': 'System settings',
                'note': 'Admin role required'
            },
            '/api/internal/debug': {
                'methods': ['GET'],
                'auth_required': True,
                'description': 'Debug information and system metrics',
                'note': 'Internal use only - requires special token'
            }
        },
        'authentication': {
            'type': 'Bearer token',
            'header': 'Authorization: Bearer <token>',
            'example_token': 'sk_live_a1b2c3d4e5f6g7h8i9j0',
            'token_expiry': '1 hour',
            'refresh_endpoint': '/api/auth/refresh'
        },
        'rate_limiting': {
            'anonymous': '60 requests per minute',
            'authenticated': '300 requests per minute',
            'admin': 'unlimited'
        }
    }
    
    classification = {'attack_type': None, 'payload_family': None, 'complexity_score': 0, 'mitre_attack': None}
    add_realistic_timing('/api/docs')
    log_request('api_docs', 200, classification, False, 'known_endpoint')
    
    return jsonify(docs), 200

@app.route('/api/file')
def file_download():
    """Intentionally vulnerable file download - HONEY TRAP"""
    filename = request.args.get('name', '')
    
    classification = classify_attack('/api/file', str(request.args), 'GET', '')
    
    # Directory traversal attempt - pretend it works!
    if '..' in filename or '/' in filename or '\\' in filename:
        fake_content = {
            'success': True,
            'filename': filename,
            'content': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin',
            'message': 'File retrieved successfully',
            'size': 245,
            'mime_type': 'text/plain'
        }
        
        add_realistic_timing('/api/file')
        log_request('file_download_traversal', 200, classification, False, 'honey_trap', llm_tokens=0, llm_cost=0.0, latency_ms=0)
        
        return jsonify(fake_content), 200
    else:
        # Normal file request
        return jsonify({
            'success': False,
            'error': 'File not found',
            'code': 'NOT_FOUND'
        }), 404

@app.route('/api/login', methods=['POST'])
def login():
    """Realistic login with some working credentials (honey trap)"""
    try:
        data = request.get_json() or {}
    except:
        data = {}
    
    username = data.get('username', '')
    password = data.get('password', '')
    
    classification = classify_attack('/api/login', '', 'POST', str(data))
    
    # Allow some common combinations to "work" - trap them deeper
    valid_combos = [
        ('admin', 'admin123'),
        ('admin', 'password'),
        ('test', 'test'),
        ('root', 'root'),
        ('administrator', 'admin')
    ]
    
    add_realistic_timing('/api/login')
    
    if (username, password) in valid_combos:
        # Generate session token
        token = generate_session_token()
        fake_sessions[token] = {
            'username': username,
            'created': datetime.utcnow().isoformat(),
            'ip': request.remote_addr,
            'role': 'admin' if username == 'admin' else 'user'
        }
        
        response_data = {
            'success': True,
            'message': 'Login successful',
            'token': token,
            'expires_in': 3600,
            'user': {
                'username': username,
                'role': 'admin' if username == 'admin' else 'user',
                'permissions': ['read', 'write', 'delete'] if username == 'admin' else ['read'],
                'api_key': f"sk_live_{hashlib.md5(username.encode()).hexdigest()[:20]}"
            }
        }
        
        log_request('login_success', 200, classification, False, 'honey_trap')
        
        resp = make_response(jsonify(response_data), 200)
        resp.set_cookie('session_token', token, httponly=True, max_age=3600)
        return resp
    else:
        # Realistic delay on failure (brute force protection simulation)
        time.sleep(random.uniform(0.5, 1.5))
        
        log_request('login_failed', 401, classification, False, 'known_pattern')
        
        return jsonify({
            'success': False,
            'error': 'Invalid username or password',
            'code': 'AUTH_FAILED',
            'remaining_attempts': 3
        }), 401

@app.route('/api/admin')
@app.route('/api/admin/')
@app.route('/admin')
@app.route('/admin/')
def admin_panel():
    """Fake admin panel that checks for session"""
    
    # Check for session token
    token = request.cookies.get('session_token')
    
    classification = classify_attack(request.path, '', 'GET', '')
    add_realistic_timing(request.path)
    
    if token and token in fake_sessions:
        session_info = fake_sessions[token]
        
        # They're "logged in" - show fake admin panel
        admin_data = {
            'success': True,
            'message': 'Admin Dashboard',
            'user': session_info['username'],
            'role': session_info['role'],
            'stats': {
                'total_users': 1247,
                'active_sessions': 34,
                'server_uptime': '45 days, 3 hours',
                'database_size': '2.4 GB',
                'api_requests_today': 8934,
                'failed_logins_today': 127
            },
            'recent_activity': [
                {
                    'user': 'john_doe',
                    'action': 'login',
                    'timestamp': '2024-10-22T10:30:00Z',
                    'ip': '192.168.1.100'
                },
                {
                    'user': 'admin',
                    'action': 'user_update',
                    'timestamp': '2024-10-22T09:15:00Z',
                    'ip': '192.168.1.50'
                },
                {
                    'user': 'jane_smith',
                    'action': 'file_upload',
                    'timestamp': '2024-10-22T08:45:00Z',
                    'ip': '192.168.1.75'
                }
            ],
            'quick_actions': [
                {'name': 'User Management', 'url': '/api/admin/users'},
                {'name': 'System Settings', 'url': '/api/admin/settings'},
                {'name': 'View Logs', 'url': '/api/admin/logs'},
                {'name': 'Database Backup', 'url': '/api/admin/backup'},
                {'name': 'Security Settings', 'url': '/api/admin/security'}
            ],
            'system_info': {
                'php_version': '8.1.12',
                'mysql_version': '8.0.34',
                'apache_version': '2.4.57',
                'os': 'Ubuntu 22.04 LTS'
            }
        }
        
        log_request('admin_panel_authenticated', 200, classification, False, 'honey_trap')
        return jsonify(admin_data), 200
    else:
        # Not logged in
        log_request('admin_panel_forbidden', 403, classification, False, 'known_pattern')
        
        return jsonify({
            'success': False,
            'error': 'Forbidden: Admin access required',
            'code': 'FORBIDDEN',
            'required_role': 'admin',
            'login_url': '/api/login',
            'hint': 'Try admin/admin123'
        }), 403

@app.route('/api/admin/backup')
def admin_backup():
    """Fake admin backup endpoint - honey trap"""
    token = request.cookies.get('session_token')
    
    classification = classify_attack(request.path, '', 'GET', '')
    add_realistic_timing(request.path)
    
    if token and token in fake_sessions:
        # Show "available" backups
        backup_data = {
            'success': True,
            'backups': [
                {
                    'id': 1,
                    'filename': 'full_backup_2024-10-22.sql.gz',
                    'size': '245 MB',
                    'created': '2024-10-22T02:00:00Z',
                    'type': 'full',
                    'download_url': '/api/admin/backup/download?id=1'
                },
                {
                    'id': 2,
                    'filename': 'incremental_backup_2024-10-21.sql.gz',
                    'size': '89 MB',
                    'created': '2024-10-21T02:00:00Z',
                    'type': 'incremental',
                    'download_url': '/api/admin/backup/download?id=2'
                },
                {
                    'id': 3,
                    'filename': 'full_backup_2024-10-15.sql.gz',
                    'size': '238 MB',
                    'created': '2024-10-15T02:00:00Z',
                    'type': 'full',
                    'download_url': '/api/admin/backup/download?id=3'
                }
            ],
            'total': 3,
            'storage_path': '/var/backups/mysql/',
            'next_backup': '2024-10-23T02:00:00Z'
        }
        
        log_request('admin_backup_list', 200, classification, False, 'honey_trap')
        return jsonify(backup_data), 200
    else:
        log_request('admin_backup_forbidden', 403, classification, False, 'known_pattern')
        return jsonify({'success': False, 'error': 'Forbidden', 'code': 'FORBIDDEN'}), 403

@app.route('/api/admin/settings')
def admin_settings():
    """Fake admin settings endpoint"""
    token = request.cookies.get('session_token')
    
    classification = classify_attack(request.path, '', 'GET', '')
    add_realistic_timing(request.path)
    
    if token and token in fake_sessions:
        settings_data = {
            'success': True,
            'settings': {
                'site_name': 'Company API Portal',
                'site_url': 'https://api.company.local',
                'admin_email': 'admin@company.local',
                'timezone': 'UTC',
                'debug_mode': False,
                'maintenance_mode': False,
                'api_rate_limit': 300,
                'session_timeout': 3600,
                'password_policy': {
                    'min_length': 8,
                    'require_uppercase': True,
                    'require_lowercase': True,
                    'require_numbers': True,
                    'require_special': False
                },
                'database': {
                    'host': 'localhost',
                    'port': 3306,
                    'name': 'api_production',
                    'user': 'api_user'
                },
                'security': {
                    'ssl_enabled': True,
                    'csrf_protection': True,
                    'xss_protection': True,
                    'ip_whitelist': ['192.168.1.0/24'],
                    'failed_login_limit': 5,
                    'lockout_duration': 900
                }
            }
        }
        
        log_request('admin_settings', 200, classification, False, 'honey_trap')
        return jsonify(settings_data), 200
    else:
        log_request('admin_settings_forbidden', 403, classification, False, 'known_pattern')
        return jsonify({'success': False, 'error': 'Forbidden', 'code': 'FORBIDDEN'}), 403

@app.route('/api/internal/debug')
def internal_debug():
    """Fake internal debug endpoint with sensitive info - honey trap"""
    token = request.cookies.get('session_token')
    
    classification = classify_attack(request.path, '', 'GET', '')
    add_realistic_timing(request.path)
    
    # This endpoint shows "debug info" even without auth (security misconfiguration trap)
    debug_info = {
        'success': True,
        'message': 'Debug information',
        'server': {
            'hostname': 'api-server-01',
            'ip': '10.0.1.100',
            'os': 'Ubuntu 22.04.3 LTS',
            'uptime': '45 days, 3 hours, 22 minutes'
        },
        'php': {
            'version': '8.1.12',
            'memory_limit': '256M',
            'max_execution_time': 300,
            'loaded_extensions': ['mysqli', 'pdo_mysql', 'curl', 'gd', 'json']
        },
        'database': {
            'host': 'localhost',
            'port': 3306,
            'version': '8.0.34',
            'database': 'api_production',
            'username': 'api_user',
            'password': '***REDACTED***',
            'connection_pool': 10,
            'active_connections': 3
        },
        'environment': {
            'APP_ENV': 'production',
            'APP_DEBUG': 'false',
            'DB_CONNECTION': 'mysql',
            'CACHE_DRIVER': 'redis',
            'SESSION_DRIVER': 'redis',
            'REDIS_HOST': '127.0.0.1',
            'REDIS_PORT': 6379
        },
        'paths': {
            'root': '/var/www/api',
            'storage': '/var/www/api/storage',
            'logs': '/var/www/api/storage/logs',
            'cache': '/var/www/api/storage/cache',
            'uploads': '/var/www/api/storage/uploads'
        },
        'recent_errors': [
            {
                'timestamp': '2024-10-22T10:15:00Z',
                'level': 'ERROR',
                'message': 'MySQL connection timeout',
                'file': '/var/www/api/database.php',
                'line': 127
            }
        ]
    }
    
    log_request('internal_debug', 200, classification, False, 'honey_trap')
    return jsonify(debug_info), 200

# Main catch-all route
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def catch_all(path):
    """Hybrid router: 80% rules, 20% LLM"""
    
    endpoint = '/' + path if path else '/'
    query_params = dict(request.args)
    method = request.method
    
    try:
        body_data = request.get_json() or {}
    except:
        body_data = request.get_data(as_text=True)
    
    # Classify attack
    attack_classification = classify_attack(endpoint, str(query_params), str(body_data), method)
    complexity = attack_classification['complexity_score']
    
    # Route decision
    use_llm, llm_reason = should_use_llm(endpoint, query_params, method, body_data, complexity)
    
    # Generate response
    if use_llm:
        response_data, status_code, tokens, cost, latency = llm_response(
            endpoint, query_params, method, body_data, attack_classification)
    else:
        response_data, status_code = rule_based_response(
            endpoint, query_params, method, body_data, attack_classification)
        tokens, cost, latency = 0, 0.0, 0
    
    # Log
    log_request(
        response_type='hybrid_generated',
        status_code=status_code,
        attack_classification=attack_classification,
        use_llm=use_llm,
        llm_reason=llm_reason,
        llm_tokens=tokens,
        llm_cost=cost,
        latency_ms=latency
    )
    
    return jsonify(response_data), status_code

if __name__ == '__main__':
    print(f"Starting Hybrid LLM Honeypot v2.0 (Realistic Edition)")
    print(f"Target: 80% rules, 20% LLM")
    print(f"Logs: {LOG_DIR}/honeypot.jsonl")
    print(f"Features: Session tracking, Honeytokens, Realistic headers")
    app.run(host='0.0.0.0', port=5000, debug=False)