# Run all tests against both honeypots
Write-Host "Running comprehensive test suite..." -ForegroundColor Green

# Basic tests
Write-Host "`nBasic Requests..." -ForegroundColor Cyan
Invoke-RestMethod -Uri "http://localhost:8080/" | Out-Null
Invoke-RestMethod -Uri "http://localhost:8082/" | Out-Null
Invoke-RestMethod -Uri "http://localhost:8080/api/users" | Out-Null
Invoke-RestMethod -Uri "http://localhost:8082/api/users" | Out-Null

# SQL Injection tests
Write-Host "SQL Injection Tests..." -ForegroundColor Cyan
Try { Invoke-RestMethod -Uri "http://localhost:8080/api/users/1' OR '1'='1" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/api/users/1' OR '1'='1" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8080/api/users/1' OR 1=1--" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/api/users/1' OR 1=1--" } Catch {}

# Auth tests
Write-Host "Authentication Tests..." -ForegroundColor Cyan
$body = @{username="admin"; password="wrong"} | ConvertTo-Json
Try { Invoke-RestMethod -Uri "http://localhost:8080/api/login" -Method POST -Body $body -ContentType "application/json" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/api/login" -Method POST -Body $body -ContentType "application/json" } Catch {}

# Admin tests
Write-Host "Admin Access Tests..." -ForegroundColor Cyan
Try { Invoke-RestMethod -Uri "http://localhost:8080/api/admin/settings" } Catch {}
Try { Invoke-RestMethod -Uri "http://localhost:8082/api/admin/settings" } Catch {}

# Novel endpoints
Write-Host "Novel Endpoint Tests..." -ForegroundColor Cyan
Try { Invoke-RestMethod -Uri "http://localhost:8080/api/analytics/dashboard" } Catch {}
Invoke-RestMethod -Uri "http://localhost:8082/api/analytics/dashboard" | Out-Null
Try { Invoke-RestMethod -Uri "http://localhost:8080/api/reports/quarterly" } Catch {}
Invoke-RestMethod -Uri "http://localhost:8082/api/reports/quarterly" | Out-Null

Write-Host "`nTest suite complete! Check logs for results." -ForegroundColor Green
Write-Host "Run analysis: python shared\compare_all_honeypots.py baseline-logs\honeypot.jsonl llm-logs\honeypot.jsonl llm-v2-logs\honeypot.jsonl" -ForegroundColor Yellow