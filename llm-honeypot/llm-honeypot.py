from flask import Flask, request, jsonify
import logging
import json
from datetime import datetime
import os
import openai
from dotenv import load_dotenv
import time

# Load environment variables
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

# Session storage for chain-of-thought
sessions = {}

def log_request(response_type, status_code, attack_detected=False, llm_tokens=0, llm_cost=0.0, latency_ms=0):
    """Log all requests in unified JSONL format"""
    log_entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'source_ip': request.remote_addr,
        'method': request.method,
        'path': request.path,
        'query_string': request.query_string.decode(),
        'user_agent': request.headers.get('User-Agent', ''),
        'headers': dict(request.headers),
        'body': request.get_data(as_text=True)[:500],
        'response_type': response_type,
        'response_mode': 'llm',
        'status_code': status_code,
        'attack_detected': attack_detected,
        'llm_tokens': llm_tokens,
        'llm_cost': llm_cost,
        'latency_ms': latency_ms
    }
    logging.info(json.dumps(log_entry))

def get_session_id():
    """Get or create session ID for this IP"""
    ip = request.remote_addr
    if ip not in sessions:
        sessions[ip] = {'history': [], 'created': datetime.utcnow()}
    return ip

def add_to_session_history(session_id, command, response):
    """Add interaction to session history (chain-of-thought)"""
    if session_id in sessions:
        sessions[session_id]['history'].append({
            'command': command,
            'response': response,
            'timestamp': datetime.utcnow().isoformat()
        })
        # Keep only last 10 interactions
        sessions[session_id]['history'] = sessions[session_id]['history'][-10:]

def build_prompt(endpoint, query_params, method, body_data):
    """Build prompt with in-context learning and chain-of-thought"""
    
    session_id = get_session_id()
    session_history = sessions[session_id]['history']
    
    # System context
    system_prompt = """You are emulating a REST API server for a web application.
Server: nginx/1.24.0
Framework: Express 4.18.2
API Version: 2.1.0

You must respond ONLY with valid JSON. Do not include explanations or markdown.

The API has these endpoints:
- GET /api/users - Returns list of users
- GET /api/users/<id> - Returns specific user
- POST /api/login - Authenticates user
- GET /api/search?q=<query> - Searches content
- POST /api/upload - Handles file uploads
- GET /api/admin/* - Admin endpoints (should be forbidden)

When you detect attacks (SQL injection, directory traversal, etc.), respond with realistic error messages that a vulnerable API would return, including fake SQL queries or system paths."""

    # Build the user prompt
    user_prompt = f"""Current request:
Method: {method}
Path: {endpoint}
Query Parameters: {query_params}
Body: {body_data}

"""

    # Add session history for consistency (chain-of-thought)
    if session_history:
        user_prompt += "\nPrevious interactions in this session:\n"
        for interaction in session_history[-3:]:
            user_prompt += f"Request: {interaction['command']}\n"
            user_prompt += f"Response: {json.dumps(interaction['response'])[:200]}\n\n"

    # Add in-context learning examples
    examples = """
Examples of how to respond:

Example 1 - SQL Injection detected:
Request: GET /api/search?q=1' UNION SELECT password FROM users
Response: {
    "success": false,
    "error": "MySQL Error 1064: You have an error in your SQL syntax",
    "code": "SQL_ERROR",
    "details": "Error near '1' UNION SELECT password FROM users' at line 1",
    "query": "SELECT * FROM posts WHERE title LIKE '%1' UNION SELECT password FROM users%'"
}

Example 2 - Normal user request:
Request: GET /api/users
Response: {
    "success": true,
    "data": [
        {"id": 1, "username": "admin", "email": "admin@example.com", "role": "admin"},
        {"id": 2, "username": "john_doe", "email": "john@example.com", "role": "user"}
    ],
    "total": 2
}

Example 3 - Failed login:
Request: POST /api/login with {"username": "admin", "password": "wrong"}
Response: {
    "success": false,
    "error": "Invalid credentials",
    "code": "AUTH_FAILED"
}

Example 4 - Admin access attempt:
Request: GET /api/admin/settings
Response: {
    "success": false,
    "error": "Forbidden: Admin access required",
    "code": "FORBIDDEN"
}

Now respond to the current request with valid JSON only:"""

    user_prompt += examples
    
    return system_prompt, user_prompt

def call_llm(endpoint, query_params, method, body_data):
    """Call OpenAI API to generate response"""
    
    start_time = time.time()
    
    try:
        system_prompt, user_prompt = build_prompt(endpoint, query_params, method, body_data)
        
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.7,
            max_tokens=500
        )
        
        latency_ms = int((time.time() - start_time) * 1000)
        
        # Extract response
        llm_response = response['choices'][0]['message']['content'].strip()
        
        # Parse JSON response
        try:
            # Remove markdown code blocks if present
            if llm_response.startswith('```'):
                llm_response = llm_response.split('```')[1]
                if llm_response.startswith('json'):
                    llm_response = llm_response[4:]
            
            response_data = json.loads(llm_response)
        except json.JSONDecodeError:
            # Fallback if LLM doesn't return valid JSON
            response_data = {
                "success": False,
                "error": "Internal server error",
                "code": "INTERNAL_ERROR"
            }
        
        # Calculate cost (GPT-3.5-turbo pricing)
        tokens_used = response['usage']['total_tokens']
        cost = tokens_used * 0.000002
        
        # Add to session history
        session_id = get_session_id()
        add_to_session_history(session_id, f"{method} {endpoint}", response_data)
        
        return response_data, tokens_used, cost, latency_ms
        
    except Exception as e:
        logging.error(f"LLM error: {str(e)}")
        latency_ms = int((time.time() - start_time) * 1000)
        return {
            "success": False,
            "error": "Service temporarily unavailable",
            "code": "SERVICE_ERROR"
        }, 0, 0.0, latency_ms

def detect_attack(endpoint, query_params, method, body_data):
    """Simple attack detection"""
    
    attack_patterns = [
        'union', 'select', '--', ';', 'drop', 'insert', 'update', 'delete',
        '../', '..\\', 'etc/passwd', 'windows/system32',
        'exec', 'script', 'xp_', 'sp_', 'waitfor', 'sleep('
    ]
    
    check_string = f"{endpoint} {query_params} {body_data}".lower()
    
    return any(pattern in check_string for pattern in attack_patterns)

@app.after_request
def add_headers(response):
    """Add realistic headers"""
    response.headers['Server'] = 'nginx/1.24.0'
    response.headers['X-Powered-By'] = 'Express/4.18.2'
    response.headers['X-API-Version'] = '2.1.0'
    return response

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def catch_all(path):
    """All requests processed by LLM"""
    
    endpoint = '/' + path if path else '/'
    query_params = dict(request.args)
    method = request.method
    
    try:
        body_data = request.get_json() or {}
    except:
        body_data = request.get_data(as_text=True)
    
    # Detect attack
    attack_detected = detect_attack(endpoint, str(query_params), method, str(body_data))
    
    # Call LLM
    response_data, tokens, cost, latency = call_llm(endpoint, query_params, method, body_data)
    
    # Determine status code
    if response_data.get('success') == False:
        if 'FORBIDDEN' in response_data.get('code', ''):
            status_code = 403
        elif 'AUTH_FAILED' in response_data.get('code', ''):
            status_code = 401
        elif 'NOT_FOUND' in response_data.get('code', ''):
            status_code = 404
        elif 'SQL_ERROR' in response_data.get('code', '') or 'DB_ERROR' in response_data.get('code', ''):
            status_code = 500
        else:
            status_code = 400
    else:
        status_code = 200
    
    # Log request
    log_request(
        response_type='llm_generated',
        status_code=status_code,
        attack_detected=attack_detected,
        llm_tokens=tokens,
        llm_cost=cost,
        latency_ms=latency
    )
    
    return jsonify(response_data), status_code

if __name__ == '__main__':
    print(f"Starting LLM-augmented honeypot on http://0.0.0.0:5000")
    print(f"Logs: {LOG_DIR}/honeypot.jsonl")
    app.run(host='0.0.0.0', port=5000, debug=False)