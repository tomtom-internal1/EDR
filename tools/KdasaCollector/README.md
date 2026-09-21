# KDASA User-Mode ETW Collector

Consumes Windows kernel ETW in real time and writes normalized JSONL.

## Signals

- Process start/stop
- Thread start/stop
- Image load

The implementation uses Microsoft.Diagnostics.Tracing.TraceEvent. Microsoft documents KernelTraceEventParser as the parser for Windows kernel events and provides real-time session examples using EnableKernelProvider.

## Build

Requires Windows, .NET 8 SDK, and an elevated console.

```powershell
dotnet restore
dotnet build -c Release
```

## Run

```powershell
dotnet run -c Release -- --output out\\events.jsonl
```

Press Ctrl+C to stop.

## Output

Each record is one JSON object per line. Command lines may contain local user or path information, so keep captures inside the research VM.
