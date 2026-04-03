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
from pathlib import Path

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
SCRIPT_DIR = Path(__file__).parent.absolute()
LOG_DIR = SCRIPT_DIR / 'logs' / 'llm-v2-logs'
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=str(LOG_DIR / 'honeypot.jsonl'),
    level=logging.INFO,
    format='%(message)s'
)

# OpenAI client
openai.api_key = os.getenv("OPENAI_API_KEY")

# ============================================================
# COMMAND INJECTION - Fake system command outputs
# ============================================================
COMMAND_OUTPUTS = {
    'whoami':       'www-data',
    'id':           'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
    'hostname':     'prod-api-01',
    'uname':        'Linux prod-api-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux',
    'uname -a':     'Linux prod-api-01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux',
    'pwd':          '/var/www/html',
    'cat /etc/passwd': (
        'root:x:0:0:root:/root:/bin/bash\n'
        'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'
        'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n'
        'mysql:x:112:117:MySQL Server,,,:/var/lib/mysql:/bin/false\n'
        'ubuntu:x:1000:1000:Ubuntu,,,:/home/ubuntu:/bin/bash'
    ),
    'cat .env': (
        'APP_ENV=production\nAPP_DEBUG=false\nAPP_KEY=base64:kJ3mNpQ7rS1vX9zB2dF5hL8nP0qT4wY6\n'
        'DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=api_production\n'
        'DB_USERNAME=api_user\nDB_PASSWORD=P@ssw0rd123!\n'
        'API_KEY=sk_live_a1b2c3d4e5f6g7h8i9j0\n'
        'AWS_ACCESS_KEY_ID=AKIA1234567890EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n'
        'OPENAI_API_KEY=sk-proj-XXXXXXXXXXXXXXXXXXXX'
    ),
    'cat config.php': (
        '<?php\n'
        "define('DB_HOST', '127.0.0.1');\n"
        "define('DB_NAME', 'api_production');\n"
        "define('DB_USER', 'api_user');\n"
        "define('DB_PASS', 'P@ssw0rd123!');\n"
        "define('SECRET_KEY', 'f3a9c2e1d7b4k8m0');\n"
        '?>'
    ),
    'ls -la': (
        'total 96\ndrwxr-xr-x 8 www-data www-data 4096 Oct 23 09:14 .\n'
        'drwxr-xr-x 4 root     root     4096 Sep  5 12:01 ..\n'
        '-rw-r--r-- 1 www-data www-data  847 Oct 23 09:14 .env\n'
        '-rw-r--r-- 1 www-data www-data 1203 Oct 20 15:32 config.php\n'
        'drwxr-xr-x 2 www-data www-data 4096 Oct 23 09:00 logs\n'
        'drwxr-xr-x 3 www-data www-data 4096 Oct 19 08:22 uploads\n'
        '-rw-r--r-- 1 www-data www-data 8291 Oct 23 09:14 index.php'
    ),
    'ps':      (
        '  PID TTY          TIME CMD\n'
        '    1 ?        00:00:03 apache2\n'
        '  312 ?        00:02:17 php-fpm\n'
        '  614 ?        00:00:01 mysql'
    ),
    'ps aux':  (
        'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n'
        'root         1  0.0  0.2  77828  8312 ?        Ss   09:00   0:03 /usr/sbin/apache2 -k start\n'
        'www-data   312  0.1  1.4 334268 57024 ?        S    09:00   2:17 /usr/sbin/apache2 -k start\n'
        'mysql      614  0.2  3.1 1823456 126380 ?      Sl   09:00   0:01 /usr/sbin/mysqld'
    ),
    'netstat': (
        'Active Internet connections (w/o servers)\n'
        'Proto Recv-Q Send-Q Local Address           Foreign Address         State\n'
        'tcp        0      0 localhost:mysql         localhost:49832         ESTABLISHED\n'
        'tcp        0      0 prod-api-01:http        192.168.1.50:52341      ESTABLISHED'
    ),
    'netstat -an': (
        'Active Internet connections (servers and established)\n'
        'Proto Recv-Q Send-Q Local Address           Foreign Address         State\n'
        'tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n'
        'tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\n'
        'tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n'
        'tcp        0      0 prod-api-01:http        10.0.0.42:38910         ESTABLISHED'
    ),
    'ifconfig': (
        'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n'
        '        inet 10.0.0.12  netmask 255.255.255.0  broadcast 10.0.0.255\n'
        '        inet6 fe80::216:3eff:fe00:1  prefixlen 64  scopeid 0x20<link>\n'
        'lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n'
        '        inet 127.0.0.1  netmask 255.0.0.0'
    ),
    'env': (
        'SHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n'
        'HOME=/var/www\nUSER=www-data\n'
        'DB_PASSWORD=P@ssw0rd123!\nAPI_KEY=sk_live_a1b2c3d4e5f6g7h8i9j0\n'
        'AWS_ACCESS_KEY_ID=AKIA1234567890EXAMPLE\n'
        'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    ),
    'cat /etc/hosts': (
        '127.0.0.1\tlocalhost\n'
        '127.0.1.1\tprod-api-01\n'
        '10.0.0.1\tgateway\n'
        '10.0.0.20\tdb-primary\n'
        '10.0.0.21\tdb-replica\n'
        '10.0.0.30\tcache-01'
    ),
}

# Patterns for command injection detection
CMD_INJECTION_PATTERNS = [
    # Shell operators
    ' | ', '||', '&&', '; ', '\n',
    # Download/execute
    'wget', 'curl',
    # Shells / reverse shells
    'nc ', 'netcat', '/bin/bash', '/bin/sh', 'bash -i', '/dev/tcp', '/dev/udp',
    'mkfifo', 'telnet',
    # Common recon commands
    'whoami', 'id', 'uname', 'cat ', 'ls ', 'pwd', 'echo ', 'env',
    'ps ', 'ps aux', 'netstat', 'ifconfig',
    # File ops
    'chmod', 'chown', 'rm ', 'mv ', 'cp ',
    # Windows
    'powershell', 'cmd.exe', 'cmd /c',
    # Code injection
    '__import__', 'eval(', 'exec(', 'os.system',
    # Encoding / obfuscation
    'base64', '${ifs}', '$ifs$', '`',
]

def _classify_cmd_injection(payload: str) -> str:
    """Return payload family for a command injection payload."""
    p = payload.lower()
    if any(x in p for x in ['wget', 'curl']):
        return 'download-execute'
    if any(x in p for x in ['nc ', 'netcat', '/dev/tcp', 'bash -i', 'mkfifo']):
        return 'reverse-shell'
    if any(x in p for x in ['powershell', 'cmd.exe', 'cmd /c']):
        return 'windows-cmd'
    if any(x in p for x in ['__import__', 'eval(', 'exec(', 'os.system']):
        return 'code-injection'
    if any(x in p for x in [' | ', '||', '&&', '; ', '\n']):
        return 'shell-chaining'
    return 'basic-command'

def _lookup_cmd_output(command: str) -> str:
    """Find the best fake output for a given command string."""
    cmd = command.strip()
    # Exact match first
    if cmd in COMMAND_OUTPUTS:
        return COMMAND_OUTPUTS[cmd]
    # Prefix match
    for key, output in COMMAND_OUTPUTS.items():
        if cmd.startswith(key) or key in cmd:
            return output
    return f'sh: {cmd}: command not found'


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
            }, 
            'xss_detected': {
                'status_code': 400, 
                'body': {
                    'success': False, 
                    'error': 'Invalid input: HTML tags not allowed', 
                    'code': 'XSS_DETECTED',
                    'details': 'Potentially malicious content detected and blocked',
                    'sanitized_input': '{sanitized}',
                    'blocked_tags': [], # Populated dynamically
                    'security_policy': 'Content-Security-Policy: default-src \'self\'',
                    'timestamp': None # Set at runtime
                }
            },
            'path_traversal_blocked': {
                'status_code': 403,
                'body': {
                    'success': False, 
                    'error': 'Access denied: Directory traversal detected',
                    'code': 'PATH_TRAVERSAL_BLOCKED',
                    'details': 'Attempted access to restricted filesystem path',
                    'requested_path': None, 
                    'normalized_path': None,
                    'security_note': 'All file access attempts are logged and monitored'
                }
            },
            'file_not_found': {
                'status_code': 404,
                'body': {
                    'success': False, 
                    'error': 'File not found',
                    'code': 'FILE_NOT_FOUND',
                    'path': None,
                    'suggestion': 'Check the file path and try again'
                }
            }
        }
    
    def calculate_complexity(self, request_data):
        """Determine if request needs LLM or template response"""
        payload = str(request_data.get('payload', '')).lower()
        path = request_data['path'].lower()
        
        # XSS patterns - common so use template 
        xss_pattern = [
            '<script', '</script>', 'javascript:', 'onerror=', 'onload=',
            '<img', '<svg', '<iframe', '<object', '<embed',
            'alert(', 'prompt(', 'confirm(', 'document.cookie',
            '<body', 'onmouseover=', 'onclick=', '<input',
            'eval(', '<style', '<link'
        ]
        
        # Check if any XSS pattern exists in payload or path 
        xss_detected = False 
        for pattern in xss_pattern:
            if pattern in payload or pattern in path:
                xss_detected = True 
                break 
        
        if xss_detected:
            return 0.15 # returns a low complexity if found in template 
        
        # Path traversal patterns - use templates since it's common 
        path_traversal_patterns = [
            '../', '..\\', '%2e%2e/', '%2e%2e%5c',  # Basic and encoded traversal
            'etc/passwd', 'etc/shadow', 'etc/hosts',  # Common Linux targets
            'var/www', 'var/log', 'home/', 'root/',  # Linux paths
            'proc/version', 'proc/cpuinfo', 'proc/self',  # Proc filesystem
            'windows/system32', 'windows\\system32',  # Windows paths
            'boot.ini', 'win.ini',  # Windows config files
            '.bash_history', '.ssh/authorized_keys', '.ssh/id_rsa',  # SSH/shell
            'config.php', 'wp-config.php', 'database.yml',  # App configs
        ]
        
        is_path_traversal = False 
        for pattern in path_traversal_patterns:
            if pattern in payload or pattern in path:
                is_path_traversal = True 
                break
        
        if is_path_traversal:
            return 0.12 # Return low complexity

        # Command injection patterns - use template handler
        for pattern in CMD_INJECTION_PATTERNS:
            if pattern in payload or pattern in path:
                return 0.18  # Low - handled by cmd injection templates

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
        path = request_data['path'].lower()
        
        # HTML tags that indicate XSS
        xss_tags = [
            '<script', '</script>', '<img', '<svg', '<iframe', 
            '<object', '<embed', '<body', '<input', '<style', '<link'
        ]
        
        # List of JavaScript event handlers 
        xss_events = [
            'onerror=', 'onload=', 'onclick=', 'onmouseover=', 
            'onmouseout=', 'onfocus=', 'onblur='
        ]
        
        # List of dangerous JavaScript patterns 
        xss_js = [
            'javascript:', 'alert(', 'prompt(', 'confirm(',
            'eval(', 'document.cookie', 'window.location'
        ]
        
        # Check if XSS attempt detected 
        detected_tags = []
        is_xss = False
        
        # Check tags
        for tag in xss_tags:
            if tag in payload or tag in path:
                is_xss = True 
                detected_tags.append(tag.replace('<', '').replace('>', ''))
                
        # Check event handlers 
        for event in xss_events:
            if event in payload or event in path:
                is_xss = True 
                detected_tags.append(event.replace('=', ''))
        
        # Check JavaScript patterns 
        for js in xss_js:
            if js in payload or js in path:
                is_xss = True 
                detected_tags.append(js.replace('(', '').replace(')', ''))
                
        # If XSS detected, use XSS template 
        if is_xss:
            # Sanitize the input by replacing HTML characters 
            sanitized = str(request_data.get('payload', ''))
            sanitized = sanitized.replace('<', '&lt;')
            sanitized = sanitized.replace('>', '&gt;')
            sanitized = sanitized.replace('"', '&quot;')
            sanitized = sanitized.replace("'", '&#x27;')
            sanitized = sanitized.replace('/', '&#x2F;')
            
            response = {
                'status_code': 400,
                'body': {
                    'success': False, 
                    'error': 'Invalid input: HTML tags not allowed',
                    'code': 'XSS_DETECTED',
                    'details': 'Potentially malicious content detected and blocked',
                    'sanitized_input': sanitized[:200], # Limit length
                    'blocked_tags': list(set(detected_tags)), # Remove duplicates
                    'security_policy': 'Content-Security-Policy: default-src \'self\'',
                    'timestamp': datetime.now().isoformat()
                }
            }
            
            metadata = {
                'template_used': 'xss_detected',
                'response_time_ms': random.uniform(80, 140),
                'attack_type': 'xss',
                'tags_detected': len(detected_tags) 
            }
            
            time.sleep(metadata['response_time_ms'] / 1000)
            return response, metadata

        # Path traversal detection
        path_traversal_indicators = [
            '../', '..\\', '%2e%2e/', '%2e%2e%5c',
            'etc/passwd', 'etc/shadow', 'etc/hosts',
            'var/www', 'var/log', 'home/', 'root/',
            'proc/version', 'proc/cpuinfo',
            '.bash_history', '.ssh/', 'config.php',
            'wp-config.php', 'database.yml'
        ]
        
        is_path_traversal = False 
        for indicator in path_traversal_indicators:
            if indicator in payload or indicator in path:
                is_path_traversal = True 
                break 
        
        if is_path_traversal: 
            # Extract what file they're trying to access 
            full_request = payload + ' ' + path 
            
            # Map common paths to fake files 
            file_mapping = {
                'etc/passwd': 'etc_passwd',
                '/etc/passwd': 'etc_passwd',
                'etc/shadow': 'etc_shadow',
                '/etc/shadow': 'etc_shadow',
                'etc/hosts': 'etc_hosts',
                '/etc/hosts': 'etc_hosts',
                'var/www/config.php': 'var_www_config_php',
                'config.php': 'var_www_config_php',
                'var/log/apache2/access.log': 'var_log_apache_access_log',
                'var/log/mysql/error.log': 'var_log_mysql_error_log',
                '.bash_history': 'home_admin_bash_history',
                'bash_history': 'home_admin_bash_history',
                '.ssh/authorized_keys': 'ssh_authorized_keys',
                'authorized_keys': 'ssh_authorized_keys',
                'proc/version': 'proc_version',
                '/proc/version': 'proc_version',
                'proc/cpuinfo': 'proc_cpuinfo',
                '/proc/cpuinfo': 'proc_cpuinfo'
            }
            
            # Check if the attacker is trying to access a file we have 
            matched_file = None 
            for path_pattern, file_key in file_mapping.items():
                if path_pattern in full_request:
                    matched_file = file_key
                    break 
            
            # If authenticated, serve the fake file 
            if matched_file and session.system_state.get('authenticated', False):
                # Load the fake file from knowledge base 
                import json 
                import os
                from pathlib import Path 
                
                kb_path = Path(__file__).parent / 'knowledge_base' / 'fake_system_files.json'
                try:
                    with open(kb_path, 'r') as f:
                        fake_files = json.load(f)
                    
                    if matched_file in fake_files:
                        # Serve the file content 
                        response = {
                            'status_code': 200,
                            'body': fake_files[matched_file] # Raw file content, not JSON
                        }
                        
                        metadata = {
                            'template_used': 'path_traversal_allowed',
                            'response_time_ms': random.uniform(150, 250),
                            'attack_type': 'path_traversal',
                            'file_served': matched_file,
                            'authenticated': True
                        }
                        
                        time.sleep(metadata['response_time_ms'] / 1000)
                        return response, metadata
                except:
                    pass # Fall through to blocked response
            
            # If not authenticated or file not found, block access
            # Normalize the path to show what they were trying 
            normalized_path = full_request.replace('../', '/').replace('..\\', '\\')
            
            response = {
                'status_code': 403, 
                'body': {
                    'success': False, 
                    'error': 'Access denied: Directory traversal detected',
                    'code': 'PATH_TRAVERSAL_BLOCKED',
                    'details': 'Attempted access to restricted filesystem path',
                    'requested_path': full_request[:100], # Limit length 
                    'normalized_path': normalized_path[:100],
                    'security_note': 'All file access attempts are logged and monitored',
                    'hint': 'Authentication required for file access' if not session.system_state.get('authenticated') else 'Insufficient permissions'
                }
            }
            
            metadata = {
                'template_used': 'path_traversal_blocked',
                'response_time_ms': random.uniform(90, 150),
                'attack_type': 'path_traversal',
                'authenticated': session.system_state.get('authenticated', False),
                'file_requested': matched_file if matched_file else 'unknown'
            }
            
            time.sleep(metadata['response_time_ms'] / 1000)
            return response, metadata
        
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
                fake_sessions[token] = username  # register for /api/system/exec
                
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

@app.route('/api/ping', methods=['GET', 'POST'])
def api_ping():
    """Honeypot: network ping endpoint vulnerable to command injection."""
    session_id = hashlib.md5(
        f"{request.remote_addr}{request.headers.get('User-Agent', '')}".encode()
    ).hexdigest()
    session = session_manager.get_or_create_session(session_id)

    host = (request.args.get('host') or
            (request.get_json(silent=True) or {}).get('host', ''))
    attack_detected = any(p in host for p in CMD_INJECTION_PATTERNS)

    # Build fake ping output
    ping_output = (
        f"PING {host.split()[0]} ({host.split()[0]}) 56(84) bytes of data.\n"
        f"64 bytes from {host.split()[0]}: icmp_seq=1 ttl=56 time=12.3 ms\n\n"
        f"--- {host.split()[0]} ping statistics ---\n"
        f"1 packets transmitted, 1 received, 0% packet loss, time 0ms"
    )

    if attack_detected:
        # Extract injected command (everything after the operator)
        injected = ''
        for op in [' | ', '; ', '&&', '\n']:
            if op in host:
                injected = host.split(op, 1)[1].strip()
                break
        cmd_out = _lookup_cmd_output(injected) if injected else ''
        ping_output += f"\n{cmd_out}" if cmd_out else ''

    payload_family = _classify_cmd_injection(host) if attack_detected else None

    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'source_ip': request.remote_addr,
        'method': request.method,
        'path': '/api/ping',
        'query_string': request.query_string.decode(),
        'attack_detected': attack_detected,
        'attack_classification': {
            'attack_type': 'command-injection' if attack_detected else None,
            'payload_family': payload_family,
            'mitre_attack': {'tactic': 'TA0002', 'technique': 'T1059', 'sub_technique': 'T1059.004'} if attack_detected else None
        } if attack_detected else None,
        'response_type': 'ping_command_injection' if attack_detected else 'ping_normal',
    }
    logging.info(json.dumps(log_entry))
    session.add_interaction(host, ping_output, 'template', log_entry)

    response = make_response(jsonify({
        'success': True,
        'host': host.split()[0] if host else '',
        'result': ping_output,
        'latency_ms': round(random.uniform(10, 25), 1),
        'timestamp': datetime.now().isoformat(),
    }), 200)
    response.headers['Server'] = 'Apache/2.4.41 (Ubuntu)'
    return response


# In-memory session store for /api/system/exec auth
fake_sessions = {}

@app.route('/api/system/exec', methods=['POST'])
def system_exec():
    """Honeypot: authenticated system exec endpoint."""
    session_id = hashlib.md5(
        f"{request.remote_addr}{request.headers.get('User-Agent', '')}".encode()
    ).hexdigest()
    session = session_manager.get_or_create_session(session_id)

    # Auth check: cookie or Authorization header
    token = request.cookies.get('session_token') or request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token or token not in fake_sessions:
        return make_response(jsonify({'success': False, 'error': 'Authentication required'}), 401)

    body = request.get_json(silent=True) or {}
    command = body.get('command', '')
    cmd_output = _lookup_cmd_output(command)
    payload_family = _classify_cmd_injection(command)

    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'source_ip': request.remote_addr,
        'method': 'POST',
        'path': '/api/system/exec',
        'attack_detected': True,
        'attack_classification': {
            'attack_type': 'command-injection',
            'payload_family': payload_family,
            'mitre_attack': {'tactic': 'TA0002', 'technique': 'T1059', 'sub_technique': 'T1059.004'}
        },
    }
    logging.info(json.dumps(log_entry))
    session.add_interaction(command, cmd_output, 'template', log_entry)

    response = make_response(jsonify({
        'success': True,
        'command': command,
        'output': cmd_output,
        'exit_code': 0,
        'execution_time_ms': round(random.uniform(80, 200)),
        'user': 'www-data',
        'working_directory': '/var/www/html',
        'timestamp': datetime.now().isoformat(),
    }), 200)
    response.headers['Server'] = 'Apache/2.4.41 (Ubuntu)'
    return response


@app.route('/api/convert', methods=['GET', 'POST'])
def api_convert():
    """Honeypot: file conversion endpoint vulnerable to injection via filename."""
    session_id = hashlib.md5(
        f"{request.remote_addr}{request.headers.get('User-Agent', '')}".encode()
    ).hexdigest()
    session = session_manager.get_or_create_session(session_id)

    file_param = (request.args.get('file') or
                  (request.get_json(silent=True) or {}).get('file', ''))
    fmt = request.args.get('format', 'pdf')
    attack_detected = any(p in file_param for p in CMD_INJECTION_PATTERNS)

    injected_out = ''
    if attack_detected:
        for op in ['; ', ' | ', '&&', '\n']:
            if op in file_param:
                injected_cmd = file_param.split(op, 1)[1].strip()
                injected_out = _lookup_cmd_output(injected_cmd)
                break
        payload_family = _classify_cmd_injection(file_param)
    else:
        payload_family = None

    body = {
        'success': True,
        'file': file_param.split(';')[0].split('|')[0].strip(),
        'format': fmt,
        'download_url': f'/downloads/converted_{random.randint(1000,9999)}.{fmt}',
        'timestamp': datetime.now().isoformat(),
    }
    if injected_out:
        body['debug'] = f'[DEBUG] Pre-conversion hook output:\n{injected_out}'

    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'source_ip': request.remote_addr,
        'method': request.method,
        'path': '/api/convert',
        'query_string': request.query_string.decode(),
        'attack_detected': attack_detected,
        'attack_classification': {
            'attack_type': 'command-injection',
            'payload_family': payload_family,
            'mitre_attack': {'tactic': 'TA0002', 'technique': 'T1059', 'sub_technique': 'T1059.004'}
        } if attack_detected else None,
    }
    logging.info(json.dumps(log_entry))
    session.add_interaction(file_param, str(body), 'template', log_entry)

    response = make_response(jsonify(body), 200)
    response.headers['Server'] = 'Apache/2.4.41 (Ubuntu)'
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
    print("  ✓ Command Injection (OWASP A03 / MITRE T1059) [NEW]")
    print("    - /api/ping    : ping injection via host param")
    print("    - /api/system/exec : authenticated exec (login first)")
    print("    - /api/convert : file conversion injection via file param")
    print(f"\nOWASP coverage: 5/10 categories")
    print("\nStarting server on http://localhost:8082")
    print("Stats: http://localhost:8082/api/stats")
    print("="*70)
    app.run(host='0.0.0.0', port=8082, debug=True)