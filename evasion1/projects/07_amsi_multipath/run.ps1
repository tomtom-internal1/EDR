param(
  [ValidateSet("Native","Simulator")]
  [string]$Mode = "Native",
  [ValidateSet("stable","result-flip","hresult-failure","cross-path-drift")]
  [string]$Scenario = "stable",
  [ValidateRange(1,100)]
  [int]$Repeat = 3,
  [string]$InputFile
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Bin = Join-Path $Root "bin"
$Art = Join-Path $Root "artifacts"
$Out = Join-Path $Art "events.jsonl"
New-Item -ItemType Directory -Force -Path $Art | Out-Null

if ($Mode -eq "Simulator") {
    $Exe = Join-Path $Bin "07_amsi_multipath_sim.exe"
    if (!(Test-Path $Exe)) { throw "Missing simulator. Run .\build.ps1 first." }

    & $Exe "--scenario" $Scenario "--repeat" $Repeat 2>&1 |
        Tee-Object -FilePath $Out
} else {
    $Exe = Join-Path $Bin "07_amsi_multipath.exe"
    if (!(Test-Path $Exe)) { throw "Missing native binary. Run .\build.ps1 first." }

    $args = @("--repeat", "$Repeat")
    if ($InputFile) {
        if (!(Test-Path $InputFile -PathType Leaf)) {
            throw "Input file not found: $InputFile"
        }
        $args += @("--input", $InputFile)
    }

    & $Exe @args 2>&1 | Tee-Object -FilePath $Out
}

$code = $LASTEXITCODE
if ($code -ne 0) { throw "A07 exited with code $code" }

$i = 0
foreach ($line in Get-Content $Out) {
  $i++
  if ([string]::IsNullOrWhiteSpace($line)) { continue }
  try { $null = $line | ConvertFrom-Json }
  catch { throw "Invalid JSON at line $i" }
}

Write-Host "[PASS] JSONL validated: $Out"
