$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Bin = Join-Path $Root "bin"
$Artifacts = Join-Path $Root "artifacts"
New-Item -ItemType Directory -Force -Path $Artifacts | Out-Null

$names = @(
 "p01_early_bird_apc",
 "p02_threadpool_timer",
 "p03_enumwindows_callback",
 "p04_hw_breakpoint_veh",
 "p05_native_thread_introspection",
 "p06_etw_private_session",
 "p07_amsi_multipath",
 "p08_sec_image_mapping",
 "p09_socket_groundtruth",
 "p10_wait_callback",
 "p11_amsi_integrity"
)

foreach ($name in $names) {
    $exe = Join-Path $Bin ($name + ".exe")
    if (!(Test-Path $exe)) { throw "Missing $exe" }
    $out = Join-Path $Artifacts ($name + ".jsonl")
    Write-Host "[run] $name"
    & $exe 2>&1 | Tee-Object -FilePath $out
    if ($LASTEXITCODE -ne 0) { throw "$name failed with exit code $LASTEXITCODE" }
}

python.exe (Join-Path $Root "validate.py")
if ($LASTEXITCODE -ne 0) { throw "Advanced validator failed" }
