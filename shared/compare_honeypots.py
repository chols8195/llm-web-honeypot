import json
import sys
from collections import Counter

def analyze_honeypot(log_file, name):
    """Analyze single honeypot"""
    
    entries = []
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except:
                continue
    
    total = len(entries)
    attacks = [e for e in entries if e.get('attack_detected')]
    
    # Calculate metrics
    avg_latency = sum(e.get('latency_ms', 0) for e in entries) / total if total > 0 else 0
    total_tokens = sum(e.get('llm_tokens', 0) for e in entries)
    total_cost = sum(e.get('llm_cost', 0.0) for e in entries)
    
    return {
        'name': name,
        'total_requests': total,
        'attacks_detected': len(attacks),
        'attack_rate': (len(attacks) / total * 100) if total > 0 else 0,
        'avg_latency_ms': avg_latency,
        'total_tokens': total_tokens,
        'total_cost': total_cost,
        'response_mode': entries[0].get('response_mode', 'unknown') if entries else 'unknown'
    }

def compare(baseline_log, llm_log):
    """Compare two honeypots"""
    
    baseline = analyze_honeypot(baseline_log, "Baseline (Rules)")
    llm = analyze_honeypot(llm_log, "LLM-Augmented")
    
    print("="*70)
    print("HONEYPOT COMPARISON")
    print("="*70)
    
    print(f"\n{'Metric':<30} {'Baseline':<20} {'LLM-Augmented':<20}")
    print("-"*70)
    
    print(f"{'Total Requests':<30} {baseline['total_requests']:<20} {llm['total_requests']:<20}")
    print(f"{'Attacks Detected':<30} {baseline['attacks_detected']:<20} {llm['attacks_detected']:<20}")
    print(f"{'Attack Rate':<30} {baseline['attack_rate']:<19.1f}% {llm['attack_rate']:<19.1f}%")
    print(f"{'Avg Latency (ms)':<30} {baseline['avg_latency_ms']:<20.1f} {llm['avg_latency_ms']:<20.1f}")
    print(f"{'Total LLM Tokens':<30} {baseline['total_tokens']:<20} {llm['total_tokens']:<20}")
    print(f"{'Total Cost ($)':<30} ${baseline['total_cost']:<19.4f} ${llm['total_cost']:<19.4f}")
    
    print("\n" + "="*70)
    
    # Performance analysis
    print("\nPERFORMANCE ANALYSIS")
    print("-"*70)
    
    if baseline['avg_latency_ms'] > 0 and llm['avg_latency_ms'] > baseline['avg_latency_ms']:
        slowdown = ((llm['avg_latency_ms'] / baseline['avg_latency_ms']) - 1) * 100
        print(f"LLM is {slowdown:.1f}% slower than baseline")
    elif llm['avg_latency_ms'] > 0:
        print(f"LLM average response time: {llm['avg_latency_ms']:.1f}ms")
    
    if llm['total_cost'] > 0:
        cost_per_request = llm['total_cost'] / llm['total_requests']
        print(f"Cost per LLM request: ${cost_per_request:.6f}")
        
        if llm['total_requests'] > 0:
            print(f"Estimated cost for 1000 requests: ${cost_per_request * 1000:.2f}")
    
    print("\n" + "="*70)
    
if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python compare_honeypots.py <baseline_log> <llm_log>")
        sys.exit(1)
    
    compare(sys.argv[1], sys.argv[2])