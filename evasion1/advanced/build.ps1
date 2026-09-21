$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Out = Join-Path $Root "bin"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

function Build-Exe {
    param([string]$Name)
    $src = Join-Path $Root ($Name + ".c")
    $out = Join-Path $Out ($Name + ".exe")
    $libs = @()
    if ($Name -eq "p06_etw_private_session") { $libs += "advapi32.lib" }
    if ($Name -eq "p07_amsi_multipath") { $libs += "amsi.lib" }
    if ($Name -eq "p11_amsi_integrity") { $libs += "amsi.lib"; $libs += "bcrypt.lib" }
    if ($Name -eq "p09_socket_groundtruth") { $libs += "Ws2_32.lib"; $libs += "Iphlpapi.lib" }

    Write-Host "[build] $Name"
    & cl.exe /nologo /std:c11 /W4 /WX /O2 /EHsc /Fe:"$out" "$src" $libs
    if ($LASTEXITCODE -ne 0) { throw "cl.exe failed for $Name" }
}

Build-Exe "p01_early_bird_apc"
Build-Exe "p02_threadpool_timer"
Build-Exe "p03_enumwindows_callback"
Build-Exe "p04_hw_breakpoint_veh"
Build-Exe "p05_native_thread_introspection"
Build-Exe "p06_etw_private_session"
Build-Exe "p07_amsi_multipath"
Build-Exe "p08_sec_image_mapping"
Build-Exe "p09_socket_groundtruth"
Build-Exe "p10_wait_callback"

$baseBin = Join-Path (Split-Path $Root -Parent) "bin\evasion1_fixture.dll"
$fixture = Join-Path $Out "evasion1_fixture.dll"
if (!(Test-Path $baseBin)) {
    throw "Missing base fixture DLL: $baseBin. Run the top-level evasion1 build first."
}
Copy-Item $baseBin $fixture -Force

Write-Host "[build] complete"

Build-Exe "p11_amsi_integrity"
