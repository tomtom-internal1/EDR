$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

$required = @(
    "main.c",
    "poc_common.h",
    "build.ps1",
    "run.ps1",
    "CMakeLists.txt",
    "README.md",
    "scenario.json"
)

$projects = Get-ChildItem -Path $Root -Directory |
    Where-Object { $_.Name -match '^[0-9]{2}_' }

if ($projects.Count -ne 11) {
    throw "Expected 11 standalone projects, found $($projects.Count)."
}

foreach ($project in $projects) {
    foreach ($file in $required) {
        $path = Join-Path $project.FullName $file
        if (!(Test-Path $path)) {
            throw "$($project.Name) is missing $file"
        }
    }

    $source = Get-Content (Join-Path $project.FullName "main.c") -Raw
    if ($source -notmatch '#include "poc_common\.h"') {
        throw "$($project.Name) does not use its local telemetry header."
    }

    $scenario = Get-Content (Join-Path $project.FullName "scenario.json") -Raw | ConvertFrom-Json
    if ($scenario.standalone -ne $true) {
        throw "$($project.Name) scenario.json is not marked standalone."
    }
}

Write-Host "[PASS] 11 standalone project layouts validated."
