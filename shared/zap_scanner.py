# shared/zap_scanner.py
import subprocess
import json
import time
from datetime import datetime
import os
import platform

def run_zap_baseline_scan(target_url, honeypot_name):
    """Run OWASP ZAP baseline scan using Docker"""
    
    print(f"\n{'='*70}")
    print(f"OWASP ZAP BASELINE SCAN - {honeypot_name}")
    print(f"Target: {target_url}")
    print(f"{'='*70}\n")
    
    # Create reports directory
    reports_dir = os.path.abspath('zap_reports')
    os.makedirs(reports_dir, exist_ok=True)
    
    timestamp = int(time.time())
    
    print(f"Running ZAP baseline scan...")
    print(f"This will take 2-5 minutes...\n")
    
    start_time = time.time()
    
    # Use host.docker.internal to access host from Docker
    target = target_url.replace('localhost', 'host.docker.internal')
    
    # Windows path conversion for Docker
    if platform.system() == 'Windows':
        # Convert C:\Users\... to /c/Users/... for Docker
        docker_path = reports_dir.replace('\\', '/').replace('C:', '/c').replace('c:', '/c')
    else:
        docker_path = reports_dir

    cmd = [
        'docker', 'run', '--rm',
        '-v', f'{docker_path}:/zap/wrk:rw',
        '--add-host', 'host.docker.internal:host-gateway',
        'ghcr.io/zaproxy/zaproxy:stable',
        'zap-baseline.py',
        '-t', target,
        '-J', f'report_{honeypot_name}_{timestamp}.json',
        '-r', f'report_{honeypot_name}_{timestamp}.html',
        '-w', f'report_{honeypot_name}_{timestamp}.md',
        '-I'  # Ignore warnings for now
    ]
    
    try:
        print(f"Command: {' '.join(cmd)}\n")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600
        )
        
        elapsed = time.time() - start_time
        
        print(f"\n{'='*70}")
        print(f"Scan completed in {elapsed:.1f} seconds")
        print(f"Exit code: {result.returncode}")
        print(f"{'='*70}\n")
        
        # Show output
        if result.stdout:
            print(f"ZAP Output:\n{result.stdout}")
        if result.stderr:
            print(f"ZAP Errors:\n{result.stderr}")
        
        # Check for report files
        json_file = os.path.join(reports_dir, f'report_{honeypot_name}_{timestamp}.json')
        html_file = os.path.join(reports_dir, f'report_{honeypot_name}_{timestamp}.html')
        
        if os.path.exists(json_file):
            print(f"\n✓ Reports created:")
            print(f"  - {json_file}")
            print(f"  - {html_file}")
            return parse_zap_results(json_file, honeypot_name, elapsed)
        else:
            print(f"\n✗ Report files not created")
            print(f"  Expected: {json_file}")
            
            # List what's actually in the directory
            print(f"\nFiles in zap_reports:")
            for f in os.listdir(reports_dir):
                print(f"  - {f}")
            
            return {
                'honeypot': honeypot_name,
                'url': target_url,
                'elapsed_time': elapsed,
                'exit_code': result.returncode,
                'error': 'Report files not created'
            }
    
    except subprocess.TimeoutExpired:
        print(f"ERROR: ZAP scan timed out after 10 minutes")
        return None
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return None

def parse_zap_results(json_path, honeypot_name, elapsed):
    """Parse ZAP JSON results"""
    
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
        
        # Count alerts by risk level
        risk_counts = {
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Informational': 0
        }
        
        all_alerts = []
        
        # ZAP JSON structure: site -> alerts
        if 'site' in data:
            for site in data['site']:
                if 'alerts' in site:
                    for alert in site['alerts']:
                        risk = alert.get('riskdesc', '').split()[0]
                        if risk in risk_counts:
                            risk_counts[risk] += 1
                        
                        all_alerts.append({
                            'name': alert.get('name', ''),
                            'risk': risk,
                            'confidence': alert.get('confidence', ''),
                            'description': alert.get('desc', '')[:100]
                        })
        
        total_alerts = sum(risk_counts.values())
        
        print(f"\nALERT SUMMARY:")
        print(f"  High Risk:          {risk_counts['High']}")
        print(f"  Medium Risk:        {risk_counts['Medium']}")
        print(f"  Low Risk:           {risk_counts['Low']}")
        print(f"  Informational:      {risk_counts['Informational']}")
        print(f"  Total Alerts:       {total_alerts}")
        
        if all_alerts:
            print(f"\nTop Alerts:")
            for alert in all_alerts[:5]:
                print(f"  [{alert['risk']}] {alert['name']}")
        
        return {
            'honeypot': honeypot_name,
            'elapsed_time': elapsed,
            'total_alerts': total_alerts,
            'risk_counts': risk_counts,
            'alerts': all_alerts
        }
    
    except Exception as e:
        print(f"Error parsing ZAP results: {e}")
        return None

def scan_all_honeypots():
    """Scan all three honeypots"""
    
    honeypots = [
        ('http://localhost:8080', 'baseline'),
        ('http://localhost:8081', 'llm-v1'),
        ('http://localhost:8082', 'llm-v2')
    ]
    
    all_results = []
    
    for url, name in honeypots:
        print(f"\n{'#'*70}")
        print(f"Scanning {name.upper()}")
        print(f"{'#'*70}")
        
        result = run_zap_baseline_scan(url, name)
        if result:
            all_results.append(result)
        
        time.sleep(5)  # Brief pause between scans
    
    # Compare results
    if len(all_results) >= 3:
        compare_zap_results(all_results)
    
    return all_results

def compare_zap_results(results):
    """Compare ZAP scan results across honeypots"""
    
    print(f"\n{'='*90}")
    print(f"ZAP SCAN COMPARISON - FINGERPRINTING RESISTANCE")
    print(f"{'='*90}\n")
    
    print(f"{'Metric':<30} {'Baseline':<20} {'LLM v1':<20} {'LLM v2 Hybrid':<20}")
    print(f"{'-'*90}")
    
    baseline = next((r for r in results if r['honeypot'] == 'baseline'), None)
    llm_v1 = next((r for r in results if r['honeypot'] == 'llm-v1'), None)
    llm_v2 = next((r for r in results if r['honeypot'] == 'llm-v2'), None)
    
    if baseline and llm_v1 and llm_v2:
        print(f"{'Total Alerts':<30} {baseline['total_alerts']:<20} {llm_v1['total_alerts']:<20} {llm_v2['total_alerts']:<20}")
        print(f"{'High Risk':<30} {baseline['risk_counts']['High']:<20} {llm_v1['risk_counts']['High']:<20} {llm_v2['risk_counts']['High']:<20}")
        print(f"{'Medium Risk':<30} {baseline['risk_counts']['Medium']:<20} {llm_v1['risk_counts']['Medium']:<20} {llm_v2['risk_counts']['Medium']:<20}")
        print(f"{'Low Risk':<30} {baseline['risk_counts']['Low']:<20} {llm_v1['risk_counts']['Low']:<20} {llm_v2['risk_counts']['Low']:<20}")
        
        print(f"\n{'Detection Score':<30} ", end='')
        
        # Lower is better (harder to detect)
        baseline_score = baseline['total_alerts']
        llm_v1_score = llm_v1['total_alerts']
        llm_v2_score = llm_v2['total_alerts']
        
        print(f"{baseline_score:<20} {llm_v1_score:<20} {llm_v2_score:<20}")
        
        # Determine winner
        scores = {
            'Baseline': baseline_score,
            'LLM v1': llm_v1_score,
            'LLM v2 Hybrid': llm_v2_score
        }
        
        winner = min(scores, key=scores.get)
        
        print(f"\n{'='*90}")
        print(f"FINGERPRINTING RESISTANCE WINNER: {winner}")
        print(f"(Lower alerts = Harder to detect as honeypot)")
        print(f"{'='*90}\n")
        
        # Save comparison
        with open(f'zap_comparison_{int(time.time())}.json', 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'results': results,
                'winner': winner
            }, f, indent=2)

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'all':
        # Scan all honeypots
        scan_all_honeypots()
    elif len(sys.argv) >= 3:
        # Scan single honeypot
        url = sys.argv[1]
        name = sys.argv[2]
        run_zap_baseline_scan(url, name)
    else:
        print("Usage:")
        print("  Scan all:    python zap_scanner.py all")
        print("  Scan single: python zap_scanner.py <url> <name>")
        print("\nExamples:")
        print("  python zap_scanner.py all")
        print("  python zap_scanner.py http://localhost:8080 baseline")
        sys.exit(1)