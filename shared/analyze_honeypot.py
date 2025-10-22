import json
import sys
from collections import Counter
from datetime import datetime

def analyze_logs(log_file):
    """Comprehensive honeypot log analysis"""
    
    entries = []
    
    # Load all log entries
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except:
                continue
    
    if not entries:
        print("No log entries found!")
        return
    
    # Basic stats
    total = len(entries)
    attacks = [e for e in entries if e.get('attack_detected')]
    attack_count = len(attacks)
    
    print("="*70)
    print("HONEYPOT ANALYSIS DASHBOARD")
    print("="*70)
    
    print(f"\nOVERALL STATISTICS")
    print(f"{'-'*70}")
    print(f"Total Requests:       {total}")
    print(f"Attacks Detected:     {attack_count}")
    print(f"Attack Rate:          {(attack_count/total*100):.1f}%")
    print(f"Clean Requests:       {total - attack_count}")
    
    # Attack types
    print(f"\nATTACK TYPES")
    print(f"{'-'*70}")
    attack_types = Counter([a['response_type'] for a in attacks])
    for attack_type, count in attack_types.most_common():
        print(f"  {attack_type:.<50} {count:>3}")
    
    # Source IPs
    print(f"\nTOP SOURCE IPs")
    print(f"{'-'*70}")
    source_ips = Counter([e['source_ip'] for e in entries])
    for ip, count in source_ips.most_common(10):
        is_attacker = any(a['source_ip'] == ip for a in attacks)
        flag = "[ATK]" if is_attacker else "[OK] "
        print(f"  {flag} {ip:.<45} {count:>3} requests")
    
    # Paths accessed
    print(f"\nTOP PATHS ACCESSED")
    print(f"{'-'*70}")
    paths = Counter([e['path'] for e in entries])
    for path, count in paths.most_common(10):
        print(f"  {path:.<50} {count:>3}")
    
    # User agents
    print(f"\nUSER AGENTS")
    print(f"{'-'*70}")
    user_agents = Counter([e.get('user_agent', 'Unknown') for e in entries])
    for ua, count in user_agents.most_common(5):
        ua_short = ua[:60] + "..." if len(ua) > 60 else ua
        print(f"  {ua_short:.<60} {count:>3}")
    
    # HTTP Methods
    print(f"\nHTTP METHODS")
    print(f"{'-'*70}")
    methods = Counter([e['method'] for e in entries])
    for method, count in methods.items():
        print(f"  {method:.<20} {count:>3}")
    
    # Status codes
    print(f"\nHTTP STATUS CODES")
    print(f"{'-'*70}")
    status_codes = Counter([e['status_code'] for e in entries])
    for code, count in sorted(status_codes.items()):
        print(f"  {code:.<20} {count:>3}")
    
    # Timeline
    print(f"\nTIMELINE")
    print(f"{'-'*70}")
    if entries:
        first = datetime.fromisoformat(entries[0]['timestamp'])
        last = datetime.fromisoformat(entries[-1]['timestamp'])
        duration = (last - first).total_seconds()
        print(f"  First Request:  {first.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Last Request:   {last.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Duration:       {duration:.0f} seconds ({duration/60:.1f} minutes)")
        if duration > 0:
            print(f"  Request Rate:   {total/duration:.2f} requests/second")
    
    print("\n" + "="*70)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python analyze_honeypot.py <log_file>")
        sys.exit(1)
    
    analyze_logs(sys.argv[1])