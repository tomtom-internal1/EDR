[CmdletBinding()]
param(
    [ValidateRange(1, 5000)]
    [int]$Count = 100,

    [ValidateRange(0, 5000)]
    [int]$DelayMilliseconds = 25
)

$started = 0

for ($i = 1; $i -le $Count; $i++) {
    try {
        $process = Start-Process -FilePath "$env:SystemRoot\\System32\\cmd.exe" `
            -ArgumentList "/c", "exit", "0" `
            -PassThru -WindowStyle Hidden

        $started++
        Wait-Process -Id $process.Id
    }
    catch {
        Write-Warning "Failed workload iteration $i : $($_.Exception.Message)"
    }

    if ($DelayMilliseconds -gt 0) {
        Start-Sleep -Milliseconds $DelayMilliseconds
    }
}

Write-Host "Requested launches: $Count"
Write-Host "Completed launches: $started"
