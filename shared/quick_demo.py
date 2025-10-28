# shared/quick_demo.py
import subprocess
import time
from datetime import datetime
import requests

def demo_sequence():
    """Quick demo for presentation"""
    
    print(f"\n{'='*80}")
    print(f"LLM-AUGMENTED HONEYPOT DEMO")
    print(f"{'='*80}\n")
    
    input("Press ENTER to start demo...")
    
    # Demo 1: Show endpoints
    print(f"\n{'#'*80}")
    print(f"DEMO 1: REAL API ENDPOINTS")
    print(f"{'#'*80}\n")
    
    print("Testing endpoints on Hybrid honeypot (port 8082):\n")
    endpoints = [
        ('/', 'Root endpoint'),
        ('/api/users', 'User list'),
        ('/api/search?q=test', 'Search')
    ]
    
    for endpoint, desc in endpoints:
        url = f"http://localhost:8082{endpoint}"
        print(f"{desc}: {url}")
        try:
            resp = requests.get(url, timeout=5)
            print(f"  Status: {resp.status_code}")
            print(f"  Response: {resp.text[:100]}...\n")
        except Exception as e:
            print(f"  Error: {e}\n")
        time.sleep(1)
    
    input("\nPress ENTER to continue...")
    
    # Demo 2: Response variability
    print(f"\n{'#'*80}")
    print(f"DEMO 2: RESPONSE VARIABILITY")
    print(f"{'#'*80}\n")
    
    attack = "1' OR '1'='1"
    print(f"Sending same SQLi attack 5 times:\n")
    print(f"Attack: {attack}\n")
    
    print("Baseline (always same response):")
    for i in range(3):
        try:
            resp = requests.get(f"http://localhost:8080/api/search", params={'q': attack}, timeout=5)
            print(f"  #{i+1}: {resp.text[:80]}...")
        except:
            print(f"  #{i+1}: ERROR")
        time.sleep(0.5)
    
    print("\nHybrid (may vary for complex attacks):")
    for i in range(3):
        try:
            resp = requests.get(f"http://localhost:8082/api/search", params={'q': attack}, timeout=10)
            print(f"  #{i+1}: {resp.text[:80]}...")
        except:
            print(f"  #{i+1}: ERROR")
        time.sleep(0.5)
    
    input("\nPress ENTER to continue...")
    
    # Demo 3: Speed comparison
    print(f"\n{'-'*80}")
    print(f"DEMO 3: SPEED COMPARISON")
    print(f"{'-'*80}\n")
    
    for name, port in [('Baseline', 8080), ('Hybrid', 8082)]:
        print(f"\n{name}:")
        latencies = []
        for i in range(5):
            start = time.time()
            try:
                resp = requests.get(f"http://localhost:{port}/api/search", params={'q': 'test'}, timeout=10)
                latency = (time.time() - start) * 1000
                latencies.append(latency)
                print(f"  Request {i+1}: {latency:.0f}ms")
            except:
                print(f"  Request {i+1}: ERROR")
            time.sleep(0.3)
        
        if latencies:
            print(f"  → Average: {sum(latencies)/len(latencies):.0f}ms")
    
    print(f"\n{'='*80}")
    print(f"DEMO COMPLETE")
    print(f"{'='*80}\n")

if __name__ == '__main__':
    demo_sequence()