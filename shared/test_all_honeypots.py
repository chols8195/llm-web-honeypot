# shared/test_all_honeypots.py
import subprocess
import time
from datetime import datetime

def test_honeypot(url, name, num_attacks=30):
    """Test a single honeypot"""
    print(f"\n{'='*70}")
    print(f"Testing {name}")
    print(f"{'='*70}")
    
    result = subprocess.run(
        ['python', 'automated_attacks.py', url, str(num_attacks)],
        capture_output=True,
        text=True
    )
    
    print(result.stdout)
    return result.stdout

def main():
    print(f"\nAUTOMATED HONEYPOT COMPARISON TEST")
    print(f"Started: {datetime.now()}")
    print(f"{'='*70}\n")
    
    honeypots = [
        ('http://localhost:8080', 'Baseline (Rules)'),
        ('http://localhost:8081', 'LLM v1 (100% AI)'),
        ('http://localhost:8082', 'LLM v2 (Hybrid)')
    ]
    
    results = {}
    
    for url, name in honeypots:
        results[name] = test_honeypot(url, name, num_attacks=30)
        time.sleep(2)
    
    print(f"\n{'='*70}")
    print(f"ALL TESTS COMPLETE")
    print(f"Completed: {datetime.now()}")
    print(f"{'='*70}\n")
    
    # Save combined results
    with open(f'comparison_test_{int(time.time())}.txt', 'w') as f:
        for name, output in results.items():
            f.write(f"\n{'='*70}\n")
            f.write(f"{name}\n")
            f.write(f"{'='*70}\n")
            f.write(output)
    
    print("Results saved to comparison_test_*.txt")

if __name__ == '__main__':
    main()