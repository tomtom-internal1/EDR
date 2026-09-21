Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "Starting EDDRR training server..."
python server.py --host 127.0.0.1 --port 8765 --db out\eddrr.db
