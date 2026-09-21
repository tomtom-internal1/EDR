$ErrorActionPreference="Stop"
$Root=Split-Path -Parent $MyInvocation.MyCommand.Path
$Out=Join-Path $Root "bin"
New-Item -ItemType Directory -Force -Path $Out|Out-Null
if(-not(Get-Command cl.exe -ErrorAction SilentlyContinue)){throw "cl.exe not found. Use a Visual Studio Developer PowerShell."}
& cl.exe /nologo /std:c11 /W4 /WX /O2 /EHsc  "$Root\\main.c" /Fe:"$Out\\05_native_thread_introspection.exe"
if($LASTEXITCODE-ne0){throw "MSVC build failed for A05"}
Write-Host "[PASS] Built $Out\\05_native_thread_introspection.exe"
