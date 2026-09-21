$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Out = Join-Path $Root "bin"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    throw "cl.exe not found. Use a Visual Studio Developer PowerShell."
}

& cl.exe /nologo /std:c11 /W4 /WX /O2 /EHsc "$Root\main.c" amsi.lib bcrypt.lib version.lib /Fe:"$Out\07_amsi_multipath.exe"
if ($LASTEXITCODE -ne 0) { throw "MSVC native build failed for A07" }

& cl.exe /nologo /std:c11 /W4 /WX /O2 "$Root\simulator.c" /Fe:"$Out\07_amsi_multipath_sim.exe"
if ($LASTEXITCODE -ne 0) { throw "MSVC simulator build failed for A07" }

Write-Host "[PASS] Built native and deterministic simulator binaries"
