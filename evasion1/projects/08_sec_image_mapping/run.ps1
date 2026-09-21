$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Exe = Join-Path $Root "bin\\08_sec_image_mapping.exe"
$Art = Join-Path $Root "artifacts"
$Out = Join-Path $Art "events.jsonl"
New-Item -ItemType Directory -Force -Path $Art | Out-Null
if (!(Test-Path $Exe)) { throw "Missing $Exe. Run .\\build.ps1 first." }
& $Exe 2>&1 | Tee-Object -FilePath $Out
$code = $LASTEXITCODE
if ($code -ne 0) { throw "A08 exited with code $code" }
$i = 0
foreach ($line in Get-Content $Out) {
  $i++
  if ([string]::IsNullOrWhiteSpace($line)) { continue }
  try { $null = $line | ConvertFrom-Json } catch { throw "Invalid JSON at line $i" }
}
Write-Host "[PASS] JSONL validated"
