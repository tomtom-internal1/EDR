$ErrorActionPreference = "Stop"

$Compiler = if ($env:CC) { $env:CC } else { "cl" }

Get-ChildItem -Filter "poc_r*.c" | ForEach-Object {
    if ($Compiler -eq "cl") {
        cl /nologo /W4 /O2 $_.Name
    } else {
        & $Compiler -std=c11 -Wall -Wextra -O2 $_.FullName -o ($_.BaseName + ".exe")
        if ($LASTEXITCODE -ne 0) { throw "Compiler failed for $($_.Name)" }
    }
}
