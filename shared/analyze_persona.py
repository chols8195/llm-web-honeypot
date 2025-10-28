# shared/analyze_persona.py
import json
import sys
from collections import defaultdict

def analyze_persona_consistency(log_file):
    """Analyze if LLM maintains consistent persona per IP"""
    
    entries = []
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except:
                continue
    
    # Group by IP
    by_ip = defaultdict(list)
    for entry in entries:
        ip = entry.get('source_ip', 'unknown')
        by_ip[ip].append(entry)
    
    print(f"\n{'='*70}")
    print(f"PERSONA/SESSION CONSISTENCY ANALYSIS")
    print(f"{'='*70}\n")
    
    print(f"Total Requests:       {len(entries)}")
    print(f"Unique IPs:           {len(by_ip)}")
    
    # Analyze IPs with multiple requests
    multi_request_ips = {ip: reqs for ip, reqs in by_ip.items() if len(reqs) > 1}
    
    print(f"\nIPs with Multiple Requests: {len(multi_request_ips)}")
    
    for ip, requests in multi_request_ips.items():
        print(f"\n  IP: {ip}")
        print(f"  Requests: {len(requests)}")
        
        # Check response consistency
        response_modes = [r.get('response_mode', 'unknown') for r in requests]
        print(f"  Response modes: {set(response_modes)}")
        
        # Check if attack types vary
        attack_types = [r.get('attack_classification', {}).get('attack_type') for r in requests]
        attack_types = [a for a in attack_types if a]
        if attack_types:
            print(f"  Attack types: {set(attack_types)}")
        
        # Show timing
        timestamps = [r.get('timestamp') for r in requests]
        print(f"  First request: {timestamps[0]}")
        print(f"  Last request:  {timestamps[-1]}")
    
    print(f"\n{'='*70}\n")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python analyze_persona.py <log_file>")
        sys.exit(1)
    
    analyze_persona_consistency(sys.argv[1])