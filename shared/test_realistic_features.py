# shared/test_realistic_features.py
import requests
import time

def test_realistic_features():
    """Test all new realistic features"""
    
    base_url = "http://localhost:8082"
    
    print("\n" + "="*70)
    print("TESTING REALISTIC HONEYPOT FEATURES")
    print("="*70 + "\n")
    
    # Test 1: Check realistic headers
    print("Test 1: Realistic Headers")
    resp = requests.get(f"{base_url}/")
    print(f"  Server: {resp.headers.get('Server')}")
    print(f"  X-Powered-By: {resp.headers.get('X-Powered-By')}")
    print(f"  X-API-Version: {resp.headers.get('X-API-Version')}")
    print()
    
    # Test 2: WordPress targets
    print("Test 2: WordPress Targets")
    for endpoint in ['/wp-admin', '/wp-login.php', '/wp-config.php']:
        resp = requests.get(f"{base_url}{endpoint}")
        print(f"  {endpoint}: {resp.status_code}")
    print()
    
    # Test 3: phpMyAdmin targets
    print("Test 3: phpMyAdmin Targets")
    for endpoint in ['/phpmyadmin', '/pma']:
        resp = requests.get(f"{base_url}{endpoint}")
        print(f"  {endpoint}: {resp.status_code}")
    print()
    
    # Test 4: Honeytokens in user list
    print("Test 4: Honeytokens (API Keys)")
    resp = requests.get(f"{base_url}/api/users")
    data = resp.json()
    if 'data' in data:
        for user in data['data']:
            print(f"  {user['username']}: {user.get('api_key', 'N/A')}")
    print()
    
    # Test 5: Login with weak credentials (should work - honey trap)
    print("Test 5: Weak Login (Should Succeed - Honey Trap)")
    resp = requests.post(f"{base_url}/api/login", 
                        json={'username': 'admin', 'password': 'admin123'})
    data = resp.json()
    print(f"  Status: {resp.status_code}")
    print(f"  Success: {data.get('success')}")
    if data.get('success'):
        print(f"  Token: {data.get('token', 'N/A')[:20]}...")
        token = data.get('token')
    print()
    
    # Test 6: Access admin panel with token
    if resp.status_code == 200 and data.get('success'):
        print("Test 6: Admin Panel (With Valid Session)")
        cookies = {'session_token': data.get('token')}
        resp = requests.get(f"{base_url}/api/admin", cookies=cookies)
        admin_data = resp.json()
        print(f"  Status: {resp.status_code}")
        print(f"  Success: {admin_data.get('success')}")
        if admin_data.get('success'):
            stats = admin_data.get('stats', {})
            print(f"  Total Users: {stats.get('total_users')}")
            print(f"  Active Sessions: {stats.get('active_sessions')}")
        print()
    
    # Test 7: Robots.txt with honey traps
    print("Test 7: Robots.txt (Reveals Honey Traps)")
    resp = requests.get(f"{base_url}/robots.txt")
    print(f"  Content preview:")
    print("  " + "\n  ".join(resp.text.split('\n')[:5]))
    print()
    
    # Test 8: API Documentation
    print("Test 8: API Documentation (Information Disclosure)")
    resp = requests.get(f"{base_url}/api/docs")
    docs = resp.json()
    print(f"  Endpoints documented: {len(docs.get('endpoints', {}))}")
    print(f"  Authentication type: {docs.get('authentication', {}).get('type')}")
    print()
    
    # Test 9: Directory traversal honey trap
    print("Test 9: Directory Traversal (Appears to Work - Honey Trap)")
    resp = requests.get(f"{base_url}/api/file?name=../../etc/passwd")
    data = resp.json()
    print(f"  Status: {resp.status_code}")
    print(f"  Success: {data.get('success')}")
    if data.get('success'):
        print(f"  Content preview: {data.get('content', '')[:50]}...")
    print()
    
    # Test 10: Internal debug endpoint
    print("Test 10: Debug Endpoint (No Auth Required - Misconfiguration)")
    resp = requests.get(f"{base_url}/api/internal/debug")
    debug = resp.json()
    print(f"  Status: {resp.status_code}")
    if debug.get('database'):
        print(f"  Database exposed: {debug.get('database', {}).get('host')}")
    print(f"  Environment vars: {len(debug.get('environment', {}))}")
    print()
    
    # Test 11: Backup files
    print("Test 11: Backup Files (Tempting Target)")
    resp = requests.get(f"{base_url}/backups")
    data = resp.json()
    print(f"  Status: {resp.status_code}")
    print(f"  Files available: {len(data.get('files', []))}")
    print()
    
    print("="*70)
    print("REALISTIC FEATURES TEST COMPLETE")
    print("="*70)

if __name__ == '__main__':
    test_realistic_features()