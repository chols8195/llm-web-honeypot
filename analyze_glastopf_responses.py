# analyze_glastopf_responses.py
import sys
import os
import tempfile
import shutil

# Add glastopf to path
sys.path.insert(0, '/usr/local/lib/python2.7/dist-packages')

from glastopf.modules.HTTP.handler import HTTPHandler
from glastopf.modules.handlers.request_handler import RequestHandler
import glastopf.modules.events.attack as attack

def test_sql_responses():
    """Test what Glastopf returns for SQL injection"""
    
    print("=" * 70)
    print("GLASTOPF SQL INJECTION RESPONSE ANALYSIS")
    print("=" * 70)
    
    # Create temporary directory for tests
    data_dir = tempfile.mkdtemp()
    
    try:
        # Test 1: Simple SQL injection (URL encoded)
        print("\nTest 1: Simple SQL Injection (?q=' OR '1'='1)")
        print("-" * 70)
        event = attack.AttackEvent()
        # Use URL encoding: space=%20, quote=%27
        event.http_request = HTTPHandler("GET /test.php?q=%27%20OR%20%271%27=%271 HTTP/1.0", None)
        event.matched_pattern = "sqli"
        
        request_handler = RequestHandler(data_dir)
        emulator = request_handler.get_handler(event.matched_pattern)
        emulator.handle(event)
        
        response = event.http_request.get_response()
        print("Response:")
        print(response)
        print("\nResponse Length: {} chars".format(len(response)))
        print()
        
        # Test 2: SELECT user()
        print("\nTest 2: SELECT user()")
        print("-" * 70)
        event2 = attack.AttackEvent()
        event2.http_request = HTTPHandler("GET /test.php HTTP/1.0", None)
        event2.http_request.request_query = {"q": ["SELECT user()"]}
        event2.matched_pattern = "sqli"
        
        emulator2 = request_handler.get_handler(event2.matched_pattern)
        emulator2.handle(event2)
        
        response2 = event2.http_request.get_response()
        print("Response:")
        print(response2)
        print("\nResponse Length: {} chars".format(len(response2)))
        print()
        
        # Test 3: SELECT @@version
        print("\nTest 3: SELECT @@version")
        print("-" * 70)
        event3 = attack.AttackEvent()
        event3.http_request = HTTPHandler("GET /test.php HTTP/1.0", None)
        event3.http_request.request_query = {"q": ["SELECT @@version"]}
        event3.matched_pattern = "sqli"
        
        emulator3 = request_handler.get_handler(event3.matched_pattern)
        emulator3.handle(event3)
        
        response3 = event3.http_request.get_response()
        print("Response:")
        print(response3)
        print("\nResponse Length: {} chars".format(len(response3)))
        print()
        
        # Test 4: Single quote (error-based)
        print("\nTest 4: Single Quote (Error-Based)")
        print("-" * 70)
        event4 = attack.AttackEvent()
        event4.http_request = HTTPHandler("GET /test.php HTTP/1.0", None)
        event4.http_request.request_query = {"q": ["'"]}
        event4.matched_pattern = "sqli"
        
        emulator4 = request_handler.get_handler(event4.matched_pattern)
        emulator4.handle(event4)
        
        response4 = event4.http_request.get_response()
        print("Response:")
        print(response4)
        print("\nResponse Length: {} chars".format(len(response4)))
        print()
        
        # Test 5: UNION SELECT
        print("\nTest 5: UNION SELECT")
        print("-" * 70)
        event5 = attack.AttackEvent()
        event5.http_request = HTTPHandler("GET /test.php HTTP/1.0", None)
        event5.http_request.request_query = {"q": ["1' UNION SELECT username,password FROM users--"]}
        event5.matched_pattern = "sqli"
        
        emulator5 = request_handler.get_handler(event5.matched_pattern)
        emulator5.handle(event5)
        
        response5 = event5.http_request.get_response()
        print("Response:")
        print(response5)
        print("\nResponse Length: {} chars".format(len(response5)))
        print()
        
        # Test 6: Time-based SQLi
        print("\nTest 6: Time-Based SQL Injection")
        print("-" * 70)
        event6 = attack.AttackEvent()
        event6.http_request = HTTPHandler("GET /test.php HTTP/1.0", None)
        event6.http_request.request_query = {"q": ["1' AND SLEEP(5)--"]}
        event6.matched_pattern = "sqli"
        
        emulator6 = request_handler.get_handler(event6.matched_pattern)
        emulator6.handle(event6)
        
        response6 = event6.http_request.get_response()
        print("Response:")
        print(response6)
        print("\nResponse Length: {} chars".format(len(response6)))
        print()
        
    finally:
        if os.path.isdir(data_dir):
            shutil.rmtree(data_dir)
    
    print("=" * 70)
    print("KEY OBSERVATIONS:")
    print("=" * 70)
    print("1. Check if responses include:")
    print("   - Specific table names")
    print("   - Query fragments")
    print("   - Log file paths with line numbers")
    print("   - Affected tables list")
    print("2. Compare response length and detail level")
    print("3. Note consistency across similar attacks")
    print("=" * 70)

if __name__ == "__main__":
    test_sql_responses()