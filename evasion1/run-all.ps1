$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Bin = Join-Path $Root "bin"
$Artifacts = Join-Path $Root "artifacts"
New-Item -ItemType Directory -Force -Path $Artifacts | Out-Null

$programs = @(
    "p01_syscall_visibility",
    "p02_parent_context",
    "p03_apc_execution",
    "p04_timer_callback",
    "p05_memory_transition",
    "p06_dll_context",
    "p07_etw_degradation",
    "p08_ipv6_telemetry",
    "p09_local_ipc",
    "p10_kernel_sensor_integrity"
)

foreach ($name in $programs) {
    $exe = Join-Path $Bin ($name + ".exe")
    if (!(Test-Path $exe)) {
        throw "Missing binary: $exe. Run .\build.ps1 first."
    }

    $out = Join-Path $Artifacts ($name + ".jsonl")
    Write-Host "[run] $name"
    & $exe 2>&1 | Tee-Object -FilePath $out
    if ($LASTEXITCODE -ne 0) {
        throw "$name returned exit code $LASTEXITCODE"
    }

    Get-Content $out | ForEach-Object {
        if ($_.Trim().Length -gt 0) {
            $_ | ConvertFrom-Json | Out-Null
        }
    }
}

Write-Host "[run] all PoCs completed and JSON validated."
