import json
import sys

def analyze_hybrid(log_file):
    """Analyze hybrid honeypot routing decisions"""
    
    entries = []
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except:
                continue
    
    if not entries:
        print("No entries found")
        return
    
    rule_based = [e for e in entries if e.get('response_mode') == 'rule']
    llm_based = [e for e in entries if e.get('response_mode') == 'llm']
    
    total = len(entries)
    rule_pct = (len(rule_based) / total * 100) if total > 0 else 0
    llm_pct = (len(llm_based) / total * 100) if total > 0 else 0
    
    print("="*70)
    print("HYBRID HONEYPOT ANALYSIS")
    print("="*70)
    
    print(f"\nROUTING BREAKDOWN")
    print("-"*70)
    print(f"Total Requests:        {total}")
    print(f"Rule-Based (Fast):     {len(rule_based)} ({rule_pct:.1f}%)")
    print(f"LLM-Based (Slow):      {len(llm_based)} ({llm_pct:.1f}%)")
    print(f"\nTarget: 80% rules, 20% LLM")
    print(f"Actual: {rule_pct:.1f}% rules, {llm_pct:.1f}% LLM")
    
    # LLM routing reasons
    if llm_based:
        print(f"\nLLM ROUTING REASONS")
        print("-"*70)
        from collections import Counter
        reasons = Counter([e.get('llm_reason', 'unknown') for e in llm_based])
        for reason, count in reasons.most_common():
            print(f"  {reason:.<50} {count:>3}")
    
    # Performance comparison
    rule_latency = sum(e.get('latency_ms', 0) for e in rule_based) / len(rule_based) if rule_based else 0
    llm_latency = sum(e.get('latency_ms', 0) for e in llm_based) / len(llm_based) if llm_based else 0
    avg_latency = sum(e.get('latency_ms', 0) for e in entries) / total if total > 0 else 0
    
    print(f"\nPERFORMANCE")
    print("-"*70)
    print(f"Rule-Based Avg Latency:   {rule_latency:.1f}ms")
    print(f"LLM-Based Avg Latency:    {llm_latency:.1f}ms")
    print(f"Overall Avg Latency:      {avg_latency:.1f}ms")
    
    # Cost analysis
    total_tokens = sum(e.get('llm_tokens', 0) for e in entries)
    total_cost = sum(e.get('llm_cost', 0) for e in entries)
    
    print(f"\nCOST ANALYSIS")
    print("-"*70)
    print(f"Total LLM Tokens:         {total_tokens}")
    print(f"Total Cost:               ${total_cost:.4f}")
    if llm_based:
        print(f"Cost per LLM request:     ${total_cost/len(llm_based):.6f}")
    if total > 0:
        print(f"Cost per total request:   ${total_cost/total:.6f}")
        print(f"Est. cost for 1000 req:   ${(total_cost/total)*1000:.2f}")
    
    # Attack classification
    attacks = [e for e in entries if e.get('attack_detected')]
    
    print(f"\nATTACK CLASSIFICATION")
    print("-"*70)
    print(f"Attacks Detected:         {len(attacks)} ({len(attacks)/total*100:.1f}%)")
    
    if attacks:
        from collections import Counter
        attack_types = Counter([e['attack_classification']['attack_type'] 
                               for e in attacks 
                               if e.get('attack_classification', {}).get('attack_type')])
        
        print("\nAttack Types:")
        for attack_type, count in attack_types.most_common():
            print(f"  {attack_type:.<50} {count:>3}")
        
        # Complexity distribution
        complexities = [e['attack_classification']['complexity_score'] 
                       for e in attacks 
                       if e.get('attack_classification')]
        if complexities:
            avg_complexity = sum(complexities) / len(complexities)
            print(f"\nAverage Attack Complexity:  {avg_complexity:.2f}")
    
    print("\n" + "="*70)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python analyze_hybrid.py <log_file>")
        sys.exit(1)
    
    analyze_hybrid(sys.argv[1])