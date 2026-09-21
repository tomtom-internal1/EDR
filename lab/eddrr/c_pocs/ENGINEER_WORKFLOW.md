# C PoC Engineer Workflow

## Build

Linux/macOS with a C11 compiler:

    ./build.sh

Windows with MSVC:

    powershell -ExecutionPolicy Bypass -File .\build.ps1

A normal Visual Studio Developer Command Prompt is preferable for MSVC.

## Reproduce one finding

From the C PoC directory:

    ./poc_r01_wmi

Then send the JSON into the adapter:

    ./poc_r01_wmi | python c_poc_adapter.py

Or run the detector directly against a compiled C PoC:

    python c_poc_runner.py .\poc_r01_wmi.exe

## What engineers should record

- C source file
- generated synthetic event
- detector output
- root cause
- remediation
- regression test
- before/after result

The C PoCs are deliberately simple because the point of the exercise is to make the detector fail for a well-defined reason, not to reproduce a real intrusion.
