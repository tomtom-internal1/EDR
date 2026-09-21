$ErrorActionPreference="Stop"
$Root=Split-Path -Parent $MyInvocation.MyCommand.Path
$Out=Join-Path $Root "bin"
New-Item -ItemType Directory -Force -Path $Out|Out-Null
if(-not(Get-Command cl.exe -ErrorAction SilentlyContinue)){throw "cl.exe not found. Use a Visual Studio Developer PowerShell."}
& cl.exe /nologo /std:c11 /W4 /WX /O2 /EHsc "advapi32.lib" "$Root\\main.c" /Fe:"$Out\\06_etw_private_session.exe"
if($LASTEXITCODE -ne 0){throw "MSVC build failed for A06"}
Write-Host "[PASS] Built $Out\\06_etw_private_session.exe"
