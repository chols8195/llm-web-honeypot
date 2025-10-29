import subprocess
import webbrowser
import time

def run_demo():
    """Live demo script for presentation"""
    
    print("\n" + "="*80)
    print("LLM-AUGMENTED HONEYPOT - LIVE DEMONSTRATION")
    print("="*80 + "\n")
    
    input("Press ENTER to start demo...")
    
    # Part 1: Swagger API
    print("\n[1/6] Opening API Documentation (Swagger)...")
    webbrowser.open("http://localhost:8082/api-docs")
    input("\n(Show Swagger interface, try endpoints)\nPress ENTER to continue...")
    
    # Part 2: Test realistic features
    print("\n[2/6] Testing realistic honeypot features...")
    subprocess.run(['python', 'test_realistic_features.py'])
    input("\nPress ENTER to continue...")
    
    # Part 3: Quick demo
    print("\n[3/6] Running interactive demo...")
    subprocess.run(['python', 'quick_demo.py'])
    input("\nPress ENTER to continue...")
    
    # Part 4: Hybrid routing analysis
    print("\n[4/6] Analyzing hybrid routing (80/20 rule)...")
    subprocess.run(['python', 'analyze_hybrid.py', '../llm-v2-logs/honeypot.jsonl'])
    input("\nPress ENTER to continue...")
    
    # Part 5: Show comparison graphs
    print("\n[5/6] Displaying comparison graphs...")
    try:
        subprocess.run(['python', 'create_graphs.py'])
        print("\n(Graph displayed - show to audience)")
    except:
        print("Graphs unavailable (matplotlib not installed)")
    input("\nPress ENTER to continue...")
    
    # Part 6: Live attacks
    print("\n[6/6] Starting live attack simulation...")
    print("(Running 20 attacks/min for 2 minutes - press Ctrl+C to stop)\n")
    
    try:
        subprocess.run(['python', 'continuous_attacks.py', 'http://localhost:8082', '20', '2'])
    except KeyboardInterrupt:
        pass
    
    print("\n" + "="*80)
    print("DEMO COMPLETE")
    print("="*80 + "\n")
    
    # Show final comparison
    print("Generating final comparison...")
    subprocess.run(['python', 'compare_all_honeypots.py',
                   '../baseline-logs/honeypot.jsonl',
                   '../llm-logs/honeypot.jsonl',
                   '../llm-v2-logs/honeypot.jsonl'])

if __name__ == '__main__':
    run_demo()