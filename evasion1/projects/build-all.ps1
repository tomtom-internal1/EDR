$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
& (Join-Path $Root "validate-layout.ps1")

$projects = Get-ChildItem -Path $Root -Directory |
    Where-Object { $_.Name -match '^[0-9]{2}_' } |
    Sort-Object Name

foreach ($project in $projects) {
    Write-Host ""
    Write-Host "=== $($project.Name) ==="
    Push-Location $project.FullName
    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
        if ($LASTEXITCODE -ne 0) {
            throw "$($project.Name) build failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }
}

Write-Host ""
Write-Host "[PASS] All 11 standalone projects built."
