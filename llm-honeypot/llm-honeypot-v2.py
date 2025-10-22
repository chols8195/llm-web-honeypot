from flask import Flask, request, jsonify
import logging
import json
from datetime import datetime
import os
import openai
from dotenv import load_dotenv
import time
import hashlib
import random

load_dotenv()
app = Flask(__name__)
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

# Rule-based templates (80% fast path)
RULE_TEMPLATES = {
    'index': {
        'response': {
            'status': 'ok',
            'message': 'API Server v2.1.0',
            'endpoints': ['/api/login', '/api/users', '/api/search', '/api/upload', '/api/admin/settings']
        },
        'status_code': 200
    },
    'health': {
        'response': {
            'status': 'healthy',
            'timestamp': lambda: datetime.utcnow().isoformat(),
            'uptime': 3600
        },
        'status_code': 200
    },
    'users_list': {
        'response': {
            'success': True,
            'data': [
                {'id': 1, 'username': 'admin', 'email': 'admin@example.com', 'role': 'admin'},
                {'id': 2, 'username': 'john_doe', 'email': 'john@example.com', 'role': 'user'},
                {'id': 3, 'username': 'jane_smith', 'email': 'jane@example.com', 'role': 'user'}
            ],
            'total': 3
        },
        'status_code': 200
    },
    'sqli_error': {
        'response': {
            'success': False,
            'error': 'MySQL Error 1064: You have an error in your SQL syntax',
            'code': 'SQL_ERROR',
            'details': lambda payload: f"Error near '{payload}' at line 1",
            'query': lambda payload: f"SELECT * FROM posts WHERE title LIKE '%{payload}%'"
        },
        'status_code': 500
    },
    'auth_failed': {
        'response': {
            'success': False,
            'error': 'Invalid credentials',
            'code': 'AUTH_FAILED'
        },
        'status_code': 401
    },
    'forbidden': {
        'response': {
            'success': False,
            'error': 'Forbidden: Admin access required',
            'code': 'FORBIDDEN'
        },
        'status_code': 403
    },
    'not_found': {
        'response': {
            'success': False,
            'error': 'Endpoint not found',
            'code': 'NOT_FOUND'
        },
        'status_code': 404
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
    
    # Entropy (Shannon entropy) - FIXED
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
        # If entropy calculation fails, just skip it
        pass
    
    return min(score, 1.0)

def classify_attack(endpoint, query_params, body_data):
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
    
    if '/admin' in endpoint:
        return False, "known_pattern"
    
    if endpoint == '/api/login' and method == 'POST':
        return False, "known_pattern"
    
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
        # Add relevant error log
        sql_logs = [log for log in KNOWLEDGE_BASE['logs'] if 'SQL' in log['message']]
        if sql_logs:
            context.append(f"Recent log: {sql_logs[0]['message']}")
        
        # Add DB structure
        if KNOWLEDGE_BASE['db_dumps']:
            tables = [dump['table'] for dump in KNOWLEDGE_BASE['db_dumps']]
            context.append(f"Database tables: {', '.join(tables)}")
    
    if attack_type == 'directory-traversal':
        # Add config file references
        if KNOWLEDGE_BASE['configs']:
            paths = [cfg['file'] for cfg in KNOWLEDGE_BASE['configs']]
            context.append(f"System files: {', '.join(paths[:3])}")
    
    if attack_type == 'auth-brute' or attack_type == 'auth-bypass':
        # Add auth log
        auth_logs = [log for log in KNOWLEDGE_BASE['logs'] if 'login' in log['message'].lower()]
        if auth_logs:
            context.append(f"Recent auth event: {auth_logs[0]['message']}")
    
    return context

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
def add_headers(response):
    response.headers['Server'] = 'nginx/1.24.0'
    response.headers['X-Powered-By'] = 'Express/4.18.2'
    response.headers['X-API-Version'] = '2.1.0'
    return response

def rule_based_response(endpoint, query_params, method, body_data, attack_classification):
    """Fast path: Rule-based responses"""
    
    # Root
    if endpoint == '/':
        template = RULE_TEMPLATES['index']
        return template['response'], template['status_code']
    
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
        resp = template['response'].copy()
        resp['details'] = f"Error near '{str(payload)[:50]}' at line 1"
        resp['query'] = f"SELECT * FROM posts WHERE title LIKE '%{str(payload)[:50]}%'"
        return resp, template['status_code']
    
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
        return response_cache[cache_key] + (0, 0.0, int((time.time() - start_time) * 1000))
    
    try:
        # RAG: Retrieve relevant context
        kb_context = retrieve_from_kb(attack_classification['attack_type'], query_params)
        
        system_prompt = """You are emulating a REST API server (nginx/1.24.0, Express 4.18.2).
Respond ONLY with valid JSON. No explanations."""
        
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
    attack_classification = classify_attack(endpoint, str(query_params), str(body_data))
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
    print(f"Starting Hybrid LLM Honeypot v2.0")
    print(f"Target: 80% rules, 20% LLM")
    print(f"Logs: {LOG_DIR}/honeypot.jsonl")
    app.run(host='0.0.0.0', port=5000, debug=False)