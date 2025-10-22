import json
import sys

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
    
    rule_mode = [e for e in entries if e.get('response_mode') == 'rule']
    llm_mode = [e for e in entries if e.get('response_mode') == 'llm']
    
    avg_latency = sum(e.get('latency_ms', 0) for e in entries) / total if total > 0 else 0
    total_tokens = sum(e.get('llm_tokens', 0) for e in entries)
    total_cost = sum(e.get('llm_cost', 0) for e in entries)
    
    return {
        'name': name,
        'total_requests': total,
        'attacks_detected': len(attacks),
        'attack_rate': (len(attacks) / total * 100) if total > 0 else 0,
        'rule_requests': len(rule_mode),
        'llm_requests': len(llm_mode),
        'rule_pct': (len(rule_mode) / total * 100) if total > 0 else 0,
        'llm_pct': (len(llm_mode) / total * 100) if total > 0 else 0,
        'avg_latency_ms': avg_latency,
        'total_tokens': total_tokens,
        'total_cost': total_cost
    }

def compare_all(baseline_log, llm_v1_log, llm_v2_log):
    """Compare all three honeypots"""
    
    baseline = analyze_honeypot(baseline_log, "Baseline (Rules)")
    llm_v1 = analyze_honeypot(llm_v1_log, "LLM v1 (100% LLM)")
    llm_v2 = analyze_honeypot(llm_v2_log, "LLM v2 (Hybrid)")
    
    print("="*90)
    print("THREE-WAY HONEYPOT COMPARISON")
    print("="*90)
    
    print(f"\n{'Metric':<30} {'Baseline':<20} {'LLM v1':<20} {'LLM v2 Hybrid':<20}")
    print("-"*90)
    
    print(f"{'Total Requests':<30} {baseline['total_requests']:<20} {llm_v1['total_requests']:<20} {llm_v2['total_requests']:<20}")
    print(f"{'Attacks Detected':<30} {baseline['attacks_detected']:<20} {llm_v1['attacks_detected']:<20} {llm_v2['attacks_detected']:<20}")
    print(f"{'Attack Rate':<30} {baseline['attack_rate']:<19.1f}% {llm_v1['attack_rate']:<19.1f}% {llm_v2['attack_rate']:<19.1f}%")
    
    print(f"\n{'ROUTING BREAKDOWN':<30}")
    print("-"*90)
    print(f"{'Rule-Based Requests':<30} {baseline['rule_requests']:<20} {llm_v1['rule_requests']:<20} {llm_v2['rule_requests']:<20}")
    print(f"{'LLM Requests':<30} {baseline['llm_requests']:<20} {llm_v1['llm_requests']:<20} {llm_v2['llm_requests']:<20}")
    print(f"{'Rule %':<30} {baseline['rule_pct']:<19.1f}% {llm_v1['rule_pct']:<19.1f}% {llm_v2['rule_pct']:<19.1f}%")
    print(f"{'LLM %':<30} {baseline['llm_pct']:<19.1f}% {llm_v1['llm_pct']:<19.1f}% {llm_v2['llm_pct']:<19.1f}%")
    
    print(f"\n{'PERFORMANCE':<30}")
    print("-"*90)
    print(f"{'Avg Latency (ms)':<30} {baseline['avg_latency_ms']:<20.1f} {llm_v1['avg_latency_ms']:<20.1f} {llm_v2['avg_latency_ms']:<20.1f}")
    print(f"{'Total LLM Tokens':<30} {baseline['total_tokens']:<20} {llm_v1['total_tokens']:<20} {llm_v2['total_tokens']:<20}")
    print(f"{'Total Cost ($)':<30} ${baseline['total_cost']:<19.4f} ${llm_v1['total_cost']:<19.4f} ${llm_v2['total_cost']:<19.4f}")
    
    if llm_v2['total_requests'] > 0:
        cost_per_req_v2 = llm_v2['total_cost'] / llm_v2['total_requests']
        print(f"{'Cost per Request':<30} ${baseline['total_cost']/baseline['total_requests'] if baseline['total_requests'] > 0 else 0:<19.6f} ${llm_v1['total_cost']/llm_v1['total_requests'] if llm_v1['total_requests'] > 0 else 0:<19.6f} ${cost_per_req_v2:<19.6f}")
        print(f"{'Est. Cost (1000 req)':<30} ${(baseline['total_cost']/baseline['total_requests'])*1000 if baseline['total_requests'] > 0 else 0:<19.2f} ${(llm_v1['total_cost']/llm_v1['total_requests'])*1000 if llm_v1['total_requests'] > 0 else 0:<19.2f} ${cost_per_req_v2*1000:<19.2f}")
    
    print("\n" + "="*90)
    
    print("\nKEY FINDINGS")
    print("-"*90)
    
    if llm_v2['avg_latency_ms'] > 0 and llm_v1['avg_latency_ms'] > 0:
        improvement = ((llm_v1['avg_latency_ms'] - llm_v2['avg_latency_ms']) / llm_v1['avg_latency_ms']) * 100
        print(f"Hybrid v2 is {improvement:.1f}% faster than v1")
    
    if llm_v2['total_requests'] > 0 and llm_v1['total_requests'] > 0:
        v1_cost_per = llm_v1['total_cost'] / llm_v1['total_requests']
        v2_cost_per = llm_v2['total_cost'] / llm_v2['total_requests']
        if v1_cost_per > 0:
            cost_reduction = ((v1_cost_per - v2_cost_per) / v1_cost_per) * 100
            print(f"Hybrid v2 reduces costs by {cost_reduction:.1f}% vs v1")
    
    print("\n" + "="*90)

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python compare_all_honeypots.py <baseline_log> <llm_v1_log> <llm_v2_log>")
        sys.exit(1)
    
    compare_all(sys.argv[1], sys.argv[2], sys.argv[3])