$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Out = Join-Path $Root "bin"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

function Invoke-Cl {
    param([string]$Source, [string]$Output)
    Write-Host "[build] $([IO.Path]::GetFileName($Output))"
    & cl.exe /nologo /std:c11 /W4 /WX /O2 /Fe:"$Output" "$Source"
    if ($LASTEXITCODE -ne 0) {
        throw "cl.exe failed for $Output"
    }
}

function Invoke-ClDll {
    param([string]$Source, [string]$Output)
    Write-Host "[build] $([IO.Path]::GetFileName($Output))"
    & cl.exe /nologo /LD /W4 /WX /O2 /Fe:"$Output" "$Source"
    if ($LASTEXITCODE -ne 0) {
        throw "cl.exe failed for $Output"
    }
}

Invoke-Cl (Join-Path $Root "p01_syscall_visibility.c") (Join-Path $Out "p01_syscall_visibility.exe")
Invoke-Cl (Join-Path $Root "p02_parent_context.c") (Join-Path $Out "p02_parent_context.exe")
Invoke-Cl (Join-Path $Root "p03_apc_execution.c") (Join-Path $Out "p03_apc_execution.exe")
Invoke-Cl (Join-Path $Root "p04_timer_callback.c") (Join-Path $Out "p04_timer_callback.exe")
Invoke-Cl (Join-Path $Root "p05_memory_transition.c") (Join-Path $Out "p05_memory_transition.exe")
Invoke-ClDll (Join-Path $Root "p06_fixture.c") (Join-Path $Out "evasion1_fixture.dll")
Invoke-Cl (Join-Path $Root "p06_dll_context.c") (Join-Path $Out "p06_dll_context.exe")
Invoke-Cl (Join-Path $Root "p07_etw_degradation.c") (Join-Path $Out "p07_etw_degradation.exe")
Invoke-Cl (Join-Path $Root "p08_ipv6_telemetry.c") (Join-Path $Out "p08_ipv6_telemetry.exe")
Invoke-Cl (Join-Path $Root "p09_local_ipc.c") (Join-Path $Out "p09_local_ipc.exe")
Invoke-Cl (Join-Path $Root "p10_kernel_sensor_integrity.c") (Join-Path $Out "p10_kernel_sensor_integrity.exe")

Write-Host "[build] complete: $Out"
