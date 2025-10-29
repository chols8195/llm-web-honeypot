# shared/continuous_zap_scanner.py
import subprocess
import time
from datetime import datetime

def run_continuous_zap_scans(hours=24):
    """Run ZAP scans periodically"""
    
    print(f"\n{'='*80}")
    print(f"CONTINUOUS OWASP ZAP SCANNING")
    print(f"Duration: {hours} hours")
    print(f"Scanning every 2 hours")
    print(f"Started: {datetime.now()}")
    print(f"{'='*80}\n")
    
    honeypots = [
        ('http://localhost:8080', 'baseline'),
        ('http://localhost:8082', 'llm-v2')
    ]
    
    start_time = time.time()
    end_time = start_time + (hours * 3600)
    scan_count = 0
    
    # Create results log
    os.makedirs('zap_results', exist_ok=True)
    log_file = f'zap_results/continuous_scan_{int(start_time)}.txt'
    
    try:
        while time.time() < end_time:
            scan_count += 1
            
            print(f"\n{'='*80}")
            print(f"ZAP SCAN #{scan_count} - {datetime.now()}")
            print(f"{'='*80}\n")
            
            scan_results = []
            
            for url, name in honeypots:
                print(f"\nScanning {name}...")
                target = url.replace('localhost', 'host.docker.internal')
                
                try:
                    cmd = [
                        'docker', 'run', '--rm',
                        '--add-host', 'host.docker.internal:host-gateway',
                        'ghcr.io/zaproxy/zaproxy:stable',
                        'zap-baseline.py', '-t', target, '-I'
                    ]
                    
                    start = time.time()
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    elapsed = time.time() - start
                    
                    scan_results.append({
                        'timestamp': datetime.now().isoformat(),
                        'honeypot': name,
                        'exit_code': result.returncode,
                        'duration': elapsed
                    })
                    
                    print(f"  {name}: Exit code {result.returncode} ({elapsed:.0f}s)")
                    
                except subprocess.TimeoutExpired:
                    print(f"  {name}: Timeout")
                    scan_results.append({
                        'timestamp': datetime.now().isoformat(),
                        'honeypot': name,
                        'error': 'timeout'
                    })
                except Exception as e:
                    print(f"  {name}: Error - {e}")
                
                time.sleep(10)
            
            # Save results to log
            with open(log_file, 'a') as f:
                f.write(f"\n{'='*80}\n")
                f.write(f"Scan #{scan_count} - {datetime.now()}\n")
                f.write(f"{'='*80}\n")
                for r in scan_results:
                    f.write(f"{r}\n")
            
            # Sleep for 2 hours before next scan
            remaining = end_time - time.time()
            if remaining > 7200:
                print(f"\nNext ZAP scan in 2 hours...")
                time.sleep(7200)
            else:
                print(f"\nFinal scan complete")
                break
    
    except KeyboardInterrupt:
        print("\n\nStopped by user")
    
    print(f"\n{'='*80}")
    print(f"CONTINUOUS ZAP SCANNING COMPLETE")
    print(f"Total scans completed: {scan_count}")
    print(f"Results saved to: {log_file}")
    print(f"{'='*80}\n")

if __name__ == '__main__':
    import sys
    hours = int(sys.argv[1]) if len(sys.argv) > 1 else 24
    run_continuous_zap_scans(hours)