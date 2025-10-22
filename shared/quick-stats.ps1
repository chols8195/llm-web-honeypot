# Quick Honeypot Stats
$logFile = "..\baseline-logs\honeypot.jsonl"

if (-not (Test-Path $logFile)) {
    Write-Host "No log file found at $logFile"
    exit
}

# Parse JSONL correctly (one JSON object per line)
$entries = @()
Get-Content $logFile | ForEach-Object {
    try {
        $entries += ($_ | ConvertFrom-Json)
    } catch {}
}

if ($entries.Count -eq 0) {
    Write-Host "No entries found in log file"
    exit
}

$attacks = $entries | Where-Object {$_.attack_detected -eq $true}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "HONEYPOT QUICK STATS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Total Requests:    $($entries.Count)"
Write-Host "Attacks Detected:  $($attacks.Count)"
if ($entries.Count -gt 0) {
    $attackRate = ($attacks.Count / $entries.Count * 100).ToString('N1')
    Write-Host "Attack Rate:       $attackRate%"
}

Write-Host "`nRecent Attacks:" -ForegroundColor Yellow
$attacks | Select-Object -Last 5 | Select-Object timestamp, path, response_type | Format-Table -AutoSize

Write-Host "Top Attack Types:" -ForegroundColor Yellow
$attacks | Group-Object response_type | Select-Object Name, Count | Sort-Object Count -Descending | Format-Table -AutoSize