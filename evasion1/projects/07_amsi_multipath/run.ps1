param(
  [string]$InputFile,
  [ValidateRange(1,20)]
  [int]$Repeat = 2
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Exe = Join-Path $Root "bin\07_amsi_multipath.exe"
$Art = Join-Path $Root "artifacts"
$Out = Join-Path $Art "events.jsonl"

New-Item -ItemType Directory -Force -Path $Art | Out-Null
if (!(Test-Path $Exe)) { throw "Missing $Exe. Run .\build.ps1 first." }

$args = @("--repeat", "$Repeat")
if ($InputFile) {
    if (!(Test-Path $InputFile -PathType Leaf)) {
        throw "Input file not found: $InputFile"
    }
    $args += @("--input", $InputFile)
}

& $Exe @args 2>&1 | Tee-Object -FilePath $Out

$code = $LASTEXITCODE
if ($code -ne 0) { throw "A07 exited with code $code" }

$i = 0
foreach ($line in Get-Content $Out) {
  $i++
  if ([string]::IsNullOrWhiteSpace($line)) { continue }
  try { $null = $line | ConvertFrom-Json } catch {
    throw "Invalid JSON at line $i"
  }
}

Write-Host "[PASS] JSONL validated: $Out"