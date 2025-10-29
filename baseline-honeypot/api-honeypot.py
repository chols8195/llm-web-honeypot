# baseline-honeypot/api-honeypot.py 
from flask import Flask, request, jsonify
import logging
import json
from datetime import datetime
import os

app = Flask(__name__)

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

def log_request(response_type, status_code, attack_detected=False):
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
        'response_mode': 'rule',
        'status_code': status_code,
        'attack_detected': attack_detected
    }
    logging.info(json.dumps(log_entry))

# Add realistic API headers
@app.after_request
def add_headers(response):
    response.headers['Server'] = 'nginx/1.24.0'
    response.headers['X-Powered-By'] = 'Express/4.18.2'
    response.headers['X-API-Version'] = '2.1.0'
    return response

# Root endpoint
@app.route('/')
def index():
    log_request('index', 200)
    return jsonify({
        'status': 'ok',
        'message': 'API Server v2.1.0',
        'endpoints': [
            '/api/login',
            '/api/users',
            '/api/search',
            '/api/upload',
            '/api/admin/settings'
        ]
    })

# Health check
@app.route('/health')
def health():
    log_request('health', 200)
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'uptime': 3600
    })

# Login endpoint
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json() or {}
    except:
        data = {}
    
    username = data.get('username', '')
    password = data.get('password', '')
    
    # Detect attacks
    attack_detected = len(username) > 100 or len(password) > 100
    
    log_request('login_attempt', 401, attack_detected)
    
    return jsonify({
        'success': False,
        'error': 'Invalid credentials',
        'code': 'AUTH_FAILED'
    }), 401

# Users endpoint
@app.route('/api/users', methods=['GET'])
def get_users():
    log_request('users_list', 200)
    
    # Return fake user data
    return jsonify({
        'success': True,
        'data': [
            {'id': 1, 'username': 'admin', 'email': 'admin@example.com', 'role': 'admin'},
            {'id': 2, 'username': 'john_doe', 'email': 'john@example.com', 'role': 'user'},
            {'id': 3, 'username': 'jane_smith', 'email': 'jane@example.com', 'role': 'user'}
        ],
        'total': 3
    })

# Get single user
@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    # Detect SQL injection in URL parameter
    sqli_patterns = ["'", '"', '--', 'union', 'select', 'drop', 'insert', 'delete']
    attack_detected = any(pattern in str(user_id).lower() for pattern in sqli_patterns)
    
    if attack_detected:
        log_request('sqli_in_param', 500, attack_detected=True)
        return jsonify({
            'success': False,
            'error': 'Database error: You have an error in your SQL syntax near \'%s\'' % user_id,
            'code': 'DB_ERROR',
            'query': f'SELECT * FROM users WHERE id = {user_id}'
        }), 500
    
    log_request('user_detail', 404)
    return jsonify({
        'success': False,
        'error': 'User not found',
        'code': 'NOT_FOUND'
    }), 404

# Search endpoint (vulnerable to SQLi)
@app.route('/api/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    
    # Detect SQL injection
    sqli_keywords = [
        'union', 'select', '--', ';', 'drop', 'insert',
        'update', 'delete', 'exec', 'xp_', 'sp_',
        'waitfor', 'delay', 'sleep(', 'benchmark(',
        'load_file', 'into outfile', 'information_schema'
    ]
    
    attack_detected = any(keyword in query.lower() for keyword in sqli_keywords)
    
    if attack_detected:
        log_request('sqli_detected', 500, attack_detected=True)
        return jsonify({
            'success': False,
            'error': 'MySQL Error 1064: You have an error in your SQL syntax',
            'code': 'SQL_ERROR',
            'details': f'Error near \'{query[:50]}\' at line 1',
            'query': f'SELECT * FROM posts WHERE title LIKE \'%{query}%\''
        }), 500
    
    log_request('search', 200)
    return jsonify({
        'success': True,
        'data': [],
        'query': query,
        'total': 0,
        'message': 'No results found'
    })

# Upload endpoint
@app.route('/api/upload', methods=['POST'])
def upload():
    # Check for file
    if 'file' not in request.files:
        log_request('upload_no_file', 400)
        return jsonify({
            'success': False,
            'error': 'No file provided',
            'code': 'NO_FILE'
        }), 400
    
    file = request.files['file']
    filename = file.filename
    
    # Detect malicious uploads
    malicious_extensions = ['.php', '.sh', '.exe', '.bat', '.cmd', '.jsp', '.asp', '.py']
    attack_detected = any(filename.lower().endswith(ext) for ext in malicious_extensions)
    
    log_request('file_upload', 200, attack_detected)
    
    return jsonify({
        'success': True,
        'message': 'File uploaded successfully',
        'file': {
            'name': filename,
            'path': f'/uploads/2024/01/{filename}',
            'size': len(file.read()),
            'url': f'http://api.example.com/uploads/2024/01/{filename}'
        }
    })

# Admin endpoint (should be protected)
@app.route('/api/admin/settings', methods=['GET', 'POST'])
def admin_settings():
    log_request('admin_access', 403, attack_detected=True)
    return jsonify({
        'success': False,
        'error': 'Forbidden: Admin access required',
        'code': 'FORBIDDEN'
    }), 403

# Admin users endpoint
@app.route('/api/admin/users', methods=['GET'])
def admin_users():
    log_request('admin_users_access', 403, attack_detected=True)
    return jsonify({
        'success': False,
        'error': 'Forbidden: Admin access required',
        'code': 'FORBIDDEN'
    }), 403

# Database endpoint (shouldn't be exposed)
@app.route('/api/db/query', methods=['POST'])
def db_query():
    log_request('db_query_attempt', 403, attack_detected=True)
    return jsonify({
        'success': False,
        'error': 'Endpoint disabled',
        'code': 'FORBIDDEN'
    }), 403

# Config endpoint (common reconnaissance target)
@app.route('/api/config')
@app.route('/config')
@app.route('/.env')
def config():
    log_request('config_access', 403, attack_detected=True)
    return jsonify({
        'success': False,
        'error': 'Access denied',
        'code': 'FORBIDDEN'
    }), 403

# Catch directory traversal
@app.route('/<path:path>')
def catch_all(path):
    # Detect directory traversal
    traversal_patterns = ['../', '..\\', '%2e%2e', 'etc/passwd', 'windows/system32']
    attack_detected = any(pattern in path.lower() for pattern in traversal_patterns)
    
    if attack_detected:
        log_request('traversal_attempt', 403, attack_detected=True)
        return jsonify({
            'success': False,
            'error': 'Forbidden',
            'code': 'FORBIDDEN'
        }), 403
    
    log_request('not_found', 404)
    return jsonify({
        'success': False,
        'error': 'Endpoint not found',
        'code': 'NOT_FOUND',
        'path': path
    }), 404

if __name__ == '__main__':
    print(f"Starting API honeypot on http://0.0.0.0:")
    print(f"Logs: {LOG_DIR}/honeypot.jsonl")
    app.run(host='0.0.0.0', port=5000, debug=False)
    