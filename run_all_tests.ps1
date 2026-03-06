# Run all tests against ALL THREE honeypots
# Port 8080: Baseline (rule-based)
# Port 8082: LLM V2 (hybrid with XSS + Path Traversal)
# Port 8090: Google Dork Lure

Write-Host "Running comprehensive test suite against 3 honeypots..." -ForegroundColor Green
Write-Host "  - 8080: Baseline" -ForegroundColor Gray
Write-Host "  - 8082: LLM V2 (XSS + Path Traversal)" -ForegroundColor Gray
Write-Host "  - 8090: Google Dork Lure" -ForegroundColor Gray

# Basic tests
Write-Host "`nBasic Requests..." -ForegroundColor Cyan
Invoke-RestMethod -Uri "http://localhost:8080/" | Out-Null
Invoke-RestMethod -Uri "http://localhost:8082/" | Out-Null
Invoke-RestMethod -Uri "http://localhost:8090/" | Out-Null
Invoke-RestMethod -Uri "http://localhost:8080/api/users" | Out-Null
Invoke-RestMethod -Uri "http://localhost:8082/api/users" | Out-Null
Invoke-RestMethod -Uri "http://localhost:8090/api/users" | Out-Null

# SQL Injection tests
Write-Host "SQL Injection Tests..." -ForegroundColor Cyan
Try { Invoke-RestMethod -Uri "http://localhost:8080/api/users/1' OR '1'='1" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/api/users/1' OR '1'='1" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8090/api/search?q=1' UNION SELECT 1--" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8080/api/users/1' OR 1=1--" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/api/users/1' OR 1=1--" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8090/api/search?q=' OR 1=1--" } Catch {}

# XSS tests
Write-Host "XSS Tests..." -ForegroundColor Cyan
Try { Invoke-RestMethod -Uri "http://localhost:8080/api/search?q=<script>alert(1)</script>" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/api/search?q=<script>alert(1)</script>" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8090/api/search?q=<script>alert(1)</script>" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8080/api/comment?text=<img src=x onerror=alert(1)>" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/api/comment?text=<img src=x onerror=alert(1)>" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8080/api/profile?name=<svg onload=alert(document.cookie)>" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/api/profile?name=<svg onload=alert(document.cookie)>" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8080/api/search?q=<iframe src=javascript:alert(1)>" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/api/search?q=<iframe src=javascript:alert(1)>" } Catch {}

# Auth tests
Write-Host "Authentication Tests..." -ForegroundColor Cyan
$body = @{username="admin"; password="wrong"} | ConvertTo-Json
Try { Invoke-RestMethod -Uri "http://localhost:8080/api/login" -Method POST -Body $body -ContentType "application/json" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/api/login" -Method POST -Body $body -ContentType "application/json" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8090/api/login" -Method POST -Body $body -ContentType "application/json" } Catch {}

# Successful login for path traversal tests
$body = @{username="admin"; password="admin123"} | ConvertTo-Json
Try { Invoke-RestMethod -Uri "http://localhost:8080/api/login" -Method POST -Body $body -ContentType "application/json" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/api/login" -Method POST -Body $body -ContentType "application/json" } Catch {}

# Path Traversal tests
Write-Host "Path Traversal / LFI Tests..." -ForegroundColor Cyan
Try { Invoke-RestMethod -Uri "http://localhost:8080/../../../../etc/passwd" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/../../../../etc/passwd" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8090/vuln.php?page=../../../../etc/passwd" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8080/../../../../etc/shadow" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/../../../../etc/shadow" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8080/../../../../var/www/config.php" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/../../../../var/www/config.php" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8090/vuln.php?page=../../../../boot.ini" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8080/api/download?file=../../../../etc/passwd" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/api/download?file=../../../../etc/passwd" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8080/../../../../home/admin/.bash_history" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/../../../../home/admin/.bash_history" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8090/vuln.php?page=../../.env" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8080/..%2F..%2F..%2F..%2Fetc%2Fpasswd" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/..%2F..%2F..%2F..%2Fetc%2Fpasswd" } Catch {}

# Google Dork specific tests
Write-Host "Google Dork / Crawler Lure Tests..." -ForegroundColor Cyan
Try { Invoke-RestMethod -Uri "http://localhost:8090/robots.txt" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8090/sitemap.xml" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8090/wp-login.php" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8090/phpMyAdmin/" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8090/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8090/admin/login.php" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8090/portal/login" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8090/.env" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8090/config.php" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8090/server-status" } Catch {}

# Admin tests
Write-Host "Admin Access Tests..." -ForegroundColor Cyan
Try { Invoke-RestMethod -Uri "http://localhost:8080/api/admin/settings" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/api/admin/settings" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8090/api/admin/settings" } Catch {}

# Novel endpoints
Write-Host "Novel Endpoint Tests..." -ForegroundColor Cyan
Try { Invoke-RestMethod -Uri "http://localhost:8080/api/analytics/dashboard" } Catch {}
Invoke-RestMethod -Uri "http://localhost:8082/api/analytics/dashboard" | Out-Null
Try { Invoke-RestMethod -Uri "http://localhost:8080/api/reports/quarterly" } Catch {}
Invoke-RestMethod -Uri "http://localhost:8082/api/reports/quarterly" | Out-Null

Write-Host "`nTest suite complete! Check logs for results." -ForegroundColor Green
Write-Host "`nLog locations:" -ForegroundColor Yellow
Write-Host "  - Baseline:      baseline-logs\honeypot.jsonl" -ForegroundColor Gray
Write-Host "  - LLM V2:        llm-v2-logs\honeypot.jsonl" -ForegroundColor Gray
Write-Host "  - Google Dork:   googleDork\logs\dork-lure.jsonl" -ForegroundColor Gray

Write-Host "`nRun analysis:" -ForegroundColor Yellow
Write-Host "  python shared\compare_all_honeypots.py baseline-logs\honeypot.jsonl llm-logs\honeypot.jsonl llm-v2-logs\honeypot.jsonl" -ForegroundColor White

# Summary stats
Write-Host "`n=== Test Summary ===" -ForegroundColor Green
Write-Host "Attack types tested:" -ForegroundColor Cyan
Write-Host "  - SQL Injection (6 variants)" -ForegroundColor White
Write-Host "  - XSS / Reflected XSS (6 variants)" -ForegroundColor White
Write-Host "  - Path Traversal / LFI (11 variants)" -ForegroundColor White
Write-Host "  - Google Dorks (10 common paths)" -ForegroundColor White
Write-Host "  - Authentication bypass (3 tests)" -ForegroundColor White
Write-Host "  - Admin access (3 tests)" -ForegroundColor White
Write-Host "  - Novel endpoint exploration (2 tests)" -ForegroundColor White
Write-Host "`nTotal test requests: ~60" -ForegroundColor Yellow
Write-Host "Honeypots tested: 3 (Baseline, LLM V2, Google Dork)" -ForegroundColor Yellow