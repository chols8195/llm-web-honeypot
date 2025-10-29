# Continuous Attack Testing Script
# Runs automated attacks in cycles with delays

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "CONTINUOUS ATTACK TESTING" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$target = "http://localhost:8082"
$cycles = 20
$attacksPerCycle = 40
$delayMinutes = 10

Write-Host "Target:          $target"
Write-Host "Cycles:          $cycles"
Write-Host "Attacks/Cycle:   $attacksPerCycle"
Write-Host "Delay:           $delayMinutes minutes"
Write-Host "Est. Duration:   $($cycles * $delayMinutes / 60) hours`n"

$startTime = Get-Date
Write-Host "Started: $startTime`n" -ForegroundColor Green

for ($i = 1; $i -le $cycles; $i++) {
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "ATTACK CYCLE $i/$cycles" -ForegroundColor Yellow
    Write-Host "Time: $(Get-Date)" -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Yellow
    
    python automated_attacks.py $target $attacksPerCycle
    
    if ($i -lt $cycles) {
        Write-Host "`nNext cycle in $delayMinutes minutes..." -ForegroundColor Gray
        Start-Sleep -Seconds ($delayMinutes * 60)
    }
}

$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "ALL ATTACK CYCLES COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Started:  $startTime"
Write-Host "Ended:    $endTime"
Write-Host "Duration: $($duration.Hours)h $($duration.Minutes)m"
Write-Host "`nResults saved in: attack_results/`n"