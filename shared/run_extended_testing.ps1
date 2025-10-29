# Extended Testing - Run for 72 hours
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "EXTENDED CONTINUOUS TESTING - 72 HOURS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$target = "http://localhost:8082"
$durationHours = 72
$attacksPerCycle = 50
$delayMinutes = 15

$cyclesTotal = [math]::Floor($durationHours * 60 / $delayMinutes)

Write-Host "Target:          $target"
Write-Host "Duration:        $durationHours hours"
Write-Host "Attacks/Cycle:   $attacksPerCycle"
Write-Host "Delay:           $delayMinutes minutes"
Write-Host "Total Cycles:    $cyclesTotal`n"

$startTime = Get-Date
Write-Host "Started: $startTime`n" -ForegroundColor Green

for ($i = 1; $i -le $cyclesTotal; $i++) {
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "CYCLE $i/$cyclesTotal" -ForegroundColor Yellow
    Write-Host "Elapsed: $([math]::Round(($(Get-Date) - $startTime).TotalHours, 1)) hours" -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Yellow
    
    python automated_attacks.py $target $attacksPerCycle
    
    if ($i -lt $cyclesTotal) {
        Start-Sleep -Seconds ($delayMinutes * 60)
    }
}

$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "TESTING COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Duration: $($duration.TotalHours) hours"
Write-Host "Total Cycles: $i"
Write-Host "Results in: attack_results/`n"