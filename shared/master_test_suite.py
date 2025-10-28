import subprocess
import json
import time
from datetime import datetime
import os
import requests

class HoneypotTestSuite:
    """Complete testing suite for honeypot comparison"""
    
    def __init__(self):
        self.honeypots = [
            ('http://localhost:8080', 'Baseline', 'baseline'),
            ('http://localhost:8081', 'LLM_v1', 'llm-v1'),
            ('http://localhost:8082', 'LLM_v2_Hybrid', 'llm-v2')
        ]
        self.results = {}
    
    def test_1_automated_attacks(self, num_attacks=30):
        """Test 1: Automated attack suite"""
        print(f"\n{'#'*80}")
        print(f"TEST 1: AUTOMATED ATTACK TESTING ({num_attacks} attacks per honeypot)")
        print(f"{'#'*80}\n")
        
        for url, name, slug in self.honeypots:
            print(f"\n{'='*70}")
            print(f"Testing {name}...")
            print(f"{'='*70}")
            
            result = subprocess.run(
                ['python', 'automated_attacks.py', url, str(num_attacks)],
                capture_output=True,
                text=True
            )
            
            print(result.stdout)
            
            # Parse stats from output
            output = result.stdout
            if 'Average:' in output:
                # Extract avg latency
                for line in output.split('\n'):
                    if 'Average:' in line and 'ms' in line:
                        try:
                            latency = float(line.split('Average:')[1].split('ms')[0].strip())
                            self.results[f'{slug}_latency'] = latency
                        except:
                            pass
                    if 'Variability score:' in line:
                        try:
                            variability = float(line.split(':')[1].replace('%', '').strip())
                            self.results[f'{slug}_variability'] = variability
                        except:
                            pass
            
            time.sleep(2)
    
    def test_2_response_variability(self):
        """Test 2: Response variability - send same attack 10 times"""
        print(f"\n{'#'*80}")
        print(f"TEST 2: RESPONSE VARIABILITY (SAME ATTACK 10X)")
        print(f"{'#'*80}\n")
        
        attack_payload = "1' UNION SELECT username,password FROM users--"
        
        variability_results = {}
        
        for url, name, slug in self.honeypots:
            print(f"\n{name}:")
            print(f"Sending identical attack 10 times...")
            
            responses = []
            for i in range(10):
                try:
                    resp = requests.get(
                        f"{url}/api/search",
                        params={'q': attack_payload},
                        timeout=10
                    )
                    responses.append(resp.text)
                except Exception as e:
                    responses.append(str(e))
                
                time.sleep(0.5)
            
            # Count unique responses
            unique_responses = len(set(responses))
            variability_pct = (unique_responses / 10) * 100
            
            print(f"  Responses sent:      10")
            print(f"  Unique responses:    {unique_responses}")
            print(f"  Variability:         {variability_pct:.1f}%")
            
            variability_results[slug] = variability_pct
            self.results[f'{slug}_variability_test2'] = variability_pct
        
        return variability_results
    
    def test_3_session_consistency(self):
        """Test 3: Session consistency - multi-step attack from same IP"""
        print(f"\n{'#'*80}")
        print(f"TEST 3: SESSION CONSISTENCY (MULTI-STEP ATTACK)")
        print(f"{'#'*80}\n")
        
        # Simulate attacker reconnaissance -> attack sequence
        attack_sequence = [
            ("GET", "/", None, "Reconnaissance"),
            ("GET", "/api/users", None, "User enumeration"),
            ("GET", "/api/search", {'q': "' OR '1'='1"}, "SQLi attempt 1"),
            ("GET", "/api/search", {'q': "1' UNION SELECT NULL--"}, "SQLi attempt 2"),
            ("POST", "/api/login", {'username': 'admin', 'password': 'admin'}, "Login attempt"),
            ("GET", "/api/admin/settings", None, "Admin access")
        ]
        
        for url, name, slug in self.honeypots:
            print(f"\n{name}:")
            print(f"Running 6-step attack sequence...")
            
            session = requests.Session()  # Maintains session
            
            for i, (method, path, params, description) in enumerate(attack_sequence, 1):
                print(f"  Step {i}: {description:20}", end=' ')
                
                try:
                    if method == "GET":
                        resp = session.get(f"{url}{path}", params=params, timeout=10)
                    else:
                        resp = session.post(f"{url}{path}", json=params, timeout=10)
                    
                    print(f"→ {resp.status_code}")
                
                except Exception as e:
                    print(f"→ ERROR")
                
                time.sleep(0.5)
    
    def test_4_performance_stress(self):
        """Test 4: Performance under load"""
        print(f"\n{'#'*80}")
        print(f"TEST 4: PERFORMANCE STRESS TEST (50 RAPID REQUESTS)")
        print(f"{'#'*80}\n")
        
        for url, name, slug in self.honeypots:
            print(f"\n{name}:")
            
            latencies = []
            errors = 0
            
            for i in range(50):
                try:
                    start = time.time()
                    resp = requests.get(f"{url}/api/search", params={'q': 'test'}, timeout=10)
                    latency = (time.time() - start) * 1000
                    latencies.append(latency)
                except:
                    errors += 1
                
                if (i + 1) % 10 == 0:
                    print(f"  Progress: {i+1}/50")
            
            if latencies:
                avg_latency = sum(latencies)/len(latencies)
                print(f"\n  Results:")
                print(f"    Successful:    {len(latencies)}/50")
                print(f"    Errors:        {errors}/50")
                print(f"    Min latency:   {min(latencies):.0f}ms")
                print(f"    Max latency:   {max(latencies):.0f}ms")
                print(f"    Avg latency:   {avg_latency:.0f}ms")
                print(f"    Median:        {sorted(latencies)[len(latencies)//2]:.0f}ms")
                
                self.results[f'{slug}_stress_latency'] = avg_latency
    
    def test_5_log_analysis(self):
        """Test 5: Analyze collected logs"""
        print(f"\n{'#'*80}")
        print(f"TEST 5: LOG ANALYSIS")
        print(f"{'#'*80}\n")
        
        log_files = [
            ('../baseline-logs/honeypot.jsonl', 'Baseline'),
            ('../llm-logs/honeypot.jsonl', 'LLM v1'),
            ('../llm-v2-logs/honeypot.jsonl', 'LLM v2 Hybrid')
        ]
        
        for log_file, name in log_files:
            if os.path.exists(log_file):
                print(f"\n{name}:")
                
                result = subprocess.run(
                    ['python', 'analyze_honeypot.py', log_file],
                    capture_output=True,
                    text=True
                )
                
                print(result.stdout)
    
    def generate_final_report(self):
        """Generate comprehensive comparison report"""
        print(f"\n{'#'*80}")
        print(f"FINAL COMPARISON REPORT")
        print(f"{'#'*80}\n")
        
        print(f"Test Suite Completed: {datetime.now()}\n")
        
        # Summary table
        print(f"{'Metric':<40} {'Baseline':<20} {'LLM v1':<20} {'LLM v2':<20}")
        print(f"{'-'*100}")
        
        # Variability
        baseline_var = self.results.get('baseline_variability_test2', 0)
        llmv1_var = self.results.get('llm-v1_variability_test2', 0)
        llmv2_var = self.results.get('llm-v2_variability_test2', 0)
        print(f"{'Response Variability %':<40} {baseline_var:<19.1f}% {llmv1_var:<19.1f}% {llmv2_var:<19.1f}%")
        
        # Latency
        baseline_lat = self.results.get('baseline_stress_latency', 0)
        llmv1_lat = self.results.get('llm-v1_stress_latency', 0)
        llmv2_lat = self.results.get('llm-v2_stress_latency', 0)
        print(f"{'Average Latency (ms)':<40} {baseline_lat:<20.0f} {llmv1_lat:<20.0f} {llmv2_lat:<20.0f}")
        
        print(f"\n{'='*100}\n")
        
        # Key findings
        print("KEY FINDINGS:")
        if llmv2_lat > 0 and llmv1_lat > 0:
            improvement = ((llmv1_lat - llmv2_lat) / llmv1_lat) * 100
            print(f"  • Hybrid v2 is {improvement:.1f}% faster than LLM v1")
        
        if llmv2_var > baseline_var:
            print(f"  • Hybrid v2 has {llmv2_var:.0f}% response variability vs Baseline's {baseline_var:.0f}%")
        
        print(f"\n{'='*100}\n")
        
        # Save results
        with open(f'final_results_{int(time.time())}.json', 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'results': self.results
            }, f, indent=2)
        
        print(f"Results saved to final_results_{int(time.time())}.json")

def main():
    print(f"\n{'='*80}")
    print(f"COMPREHENSIVE HONEYPOT TEST SUITE")
    print(f"Started: {datetime.now()}")
    print(f"{'='*80}\n")
    
    suite = HoneypotTestSuite()
    
    # Run all tests
    suite.test_1_automated_attacks(num_attacks=30)
    suite.test_2_response_variability()
    suite.test_3_session_consistency()
    suite.test_4_performance_stress()
    suite.test_5_log_analysis()
    suite.generate_final_report()
    
    print(f"\n{'='*80}")
    print(f"ALL TESTS COMPLETE")
    print(f"Completed: {datetime.now()}")
    print(f"{'='*80}\n")

if __name__ == '__main__':
    main()