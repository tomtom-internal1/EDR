# EDDRR C PoCs

These PoCs are written in C and generate synthetic endpoint telemetry representing ten remote/RCE-style scenarios.

They are intentionally non-operational:

- no sockets
- no SMB/WMI/WinRM/RDP connections
- no remote command execution
- no process injection
- no shell execution
- no kernel interaction

Each program writes one JSON event to stdout. Engineers can compile the PoCs, capture the JSON, and feed it into the EDDRR simulator.

## Build with GCC/Clang

```text
gcc -std=c11 -Wall -Wextra -O2 poc_r01_wmi.c -o poc_r01_wmi
```

For MSVC, compile each source as C with warning level 4.

## Run

```text
./poc_r01_wmi
```

On Windows:

```text
poc_r01_wmi.exe
```

The output is synthetic JSON only.

## Ten PoCs

- R01 WMI remote execution
- R02 WinRM remote execution
- R03 SMB administrative-share activity
- R04 RDP remote session
- R05 remote service execution
- R06 remote scheduled task
- R07 PowerShell remote command syntax
- R08 Windows command shell syntax
- R09 remote file transfer
- R10 web/C2-style periodic traffic

## Engineer workflow

Compile -> run PoC -> capture JSON -> submit event to EDDRR -> reproduce miss -> inspect detection logic -> remediate -> add regression test.

