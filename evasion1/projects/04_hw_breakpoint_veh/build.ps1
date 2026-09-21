$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Out = Join-Path $Root "bin"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) { throw "cl.exe not found. Use a Visual Studio Developer PowerShell." }
& cl.exe /nologo /std:c11 /W4 /WX /O2 /EHsc  "$Root\\main.c" /Fe:"$Out\\04_hw_breakpoint_veh.exe"
if ($LASTEXITCODE -ne 0) { throw "MSVC build failed for A04" }
Write-Host "[PASS] Built $Out\\04_hw_breakpoint_veh.exe"
