# shared/run_all_tests.py
import subprocess
import time
from datetime import datetime

def run_all_tests():
    """Run complete automated test suite"""
    
    print("\n" + "="*80)
    print("AUTOMATED TESTING SUITE - LLM HONEYPOT PROJECT")
    print(f"Started: {datetime.now()}")
    print("="*80 + "\n")
    
    url = "http://localhost:8082"
    
    # Test 1: Realistic features
    print("\n[1/6] Testing realistic honeypot features...")
    subprocess.run(['python', 'test_realistic_features.py'])
    time.sleep(2)
    
    # Test 2: Automated attacks
    print("\n[2/6] Running 30 automated attacks...")
    subprocess.run(['python', 'automated_attacks.py', url, '30'])
    time.sleep(2)
    
    # Test 3: Hybrid analysis
    print("\n[3/6] Analyzing hybrid routing (80/20 split)...")
    subprocess.run(['python', 'analyze_hybrid.py', '../llm-v2-logs/honeypot.jsonl'])
    time.sleep(2)
    
    # Test 4: Persona consistency
    print("\n[4/6] Analyzing persona/session consistency...")
    subprocess.run(['python', 'analyze_persona.py', '../llm-v2-logs/honeypot.jsonl'])
    time.sleep(2)
    
    # Test 5: Compare all honeypots
    print("\n[5/6] Comparing all three honeypots...")
    subprocess.run(['python', 'compare_all_honeypots.py', 
                   '../baseline-logs/honeypot.jsonl',
                   '../llm-logs/honeypot.jsonl', 
                   '../llm-v2-logs/honeypot.jsonl'])
    time.sleep(2)
    
    # Test 6: Create graphs
    print("\n[6/6] Generating comparison graphs...")
    try:
        subprocess.run(['python', 'create_graphs.py'])
        print("Graph saved as: honeypot_comparison.png")
    except:
        print("Skipping graphs (matplotlib not installed)")
    
    print("\n" + "="*80)
    print("ALL TESTS COMPLETE")
    print(f"Finished: {datetime.now()}")
    print("="*80 + "\n")
    
    # Optional: ZAP scan
    response = input("Run OWASP ZAP scan? (takes 5 min) [y/N]: ")
    if response.lower() == 'y':
        print("\nRunning ZAP scan...")
        subprocess.run(['python', 'zap_scanner.py', url, 'llm-v2'], timeout=600)

if __name__ == '__main__':
    run_all_tests()