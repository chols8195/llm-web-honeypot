# shared/live_logs.py
import time
import json
import os
from datetime import datetime

def tail_logs(log_file, num_lines=10):
    """Show last N lines of log file"""
    
    if not os.path.exists(log_file):
        print(f"Log file not found: {log_file}")
        return
    
    print(f"\n{'='*80}")
    print(f"LIVE LOG VIEWER - {log_file}")
    print(f"{'='*80}\n")
    
    try:
        while True:
            with open(log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                recent = lines[-num_lines:]
                
                os.system('cls' if os.name == 'nt' else 'clear')
                
                print(f"\n{'='*80}")
                print(f"LIVE LOGS - Last {num_lines} entries (Updated: {datetime.now().strftime('%H:%M:%S')})")
                print(f"{'='*80}\n")
                
                for line in recent:
                    try:
                        entry = json.loads(line)
                        timestamp = entry.get('timestamp', 'N/A')[:19]
                        method = entry.get('method', 'N/A')
                        path = entry.get('path', 'N/A')
                        status = entry.get('status_code', 'N/A')
                        attack = '[!]' if entry.get('attack_detected') else '[+]'
                        
                        print(f"{attack} [{timestamp}] {method:6} {path:30} → {status}")
                    except:
                        pass
                
                print(f"\n{'='*80}")
                print("Press Ctrl+C to exit")
                
                time.sleep(2)
    
    except KeyboardInterrupt:
        print("\n\nStopped")

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python live_logs.py <log_file>")
        print("Example: python live_logs.py ../llm-v2-logs/honeypot.jsonl")
        sys.exit(1)
    
    tail_logs(sys.argv[1])