using System.Text.Json;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace KdasaCollector;

internal static class Program
{
    private const string SessionName = "KDASA-KernelTelemetry";

    public static int Main(string[] args)
    {
        var output = GetOutputPath(args);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);

        try
        {
            using var session = new TraceEventSession(SessionName);
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                session.Stop();
            };

            using var writer = new StreamWriter(output, append: true);

            session.Source.Kernel.ProcessStart += data =>
                Write(writer, new EventRecord(
                    "ProcessStart", data.TimeStamp, data.ProcessID, data.ThreadID,
                    data.ProcessName, new Dictionary<string, object?>
                    {
                        ["parentPid"] = data.ParentID,
                        ["imageFileName"] = data.ImageFileName,
                        ["commandLine"] = data.CommandLine
                    }));

            session.Source.Kernel.ProcessStop += data =>
                Write(writer, new EventRecord(
                    "ProcessStop", data.TimeStamp, data.ProcessID, data.ThreadID,
                    data.ProcessName, new Dictionary<string, object?>
                    {
                        ["parentPid"] = data.ParentID,
                        ["exitStatus"] = data.ExitStatus,
                        ["imageFileName"] = data.ImageFileName,
                        ["commandLine"] = data.CommandLine
                    }));

            session.Source.Kernel.ThreadStart += data =>
                Write(writer, new EventRecord(
                    "ThreadStart", data.TimeStamp, data.ProcessID, data.ThreadID,
                    data.ProcessName, new Dictionary<string, object?>()));

            session.Source.Kernel.ThreadStop += data =>
                Write(writer, new EventRecord(
                    "ThreadStop", data.TimeStamp, data.ProcessID, data.ThreadID,
                    data.ProcessName, new Dictionary<string, object?>()));

            session.Source.Kernel.ImageLoad += data =>
                Write(writer, new EventRecord(
                    "ImageLoad", data.TimeStamp, data.ProcessID, data.ThreadID,
                    data.ProcessName, new Dictionary<string, object?>
                    {
                        ["fileName"] = data.FileName,
                        ["baseAddress"] = $"0x{data.BaseAddress:X}",
                        ["imageSize"] = data.ImageSize,
                        ["systemModeImage"] = data.SystemModeImage
                    }));

            var keywords =
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.Thread |
                KernelTraceEventParser.Keywords.ImageLoad;

            session.EnableKernelProvider(keywords);

            Console.WriteLine("KDASA collector started.");
            Console.WriteLine($"Output: {Path.GetFullPath(output)}");
            Console.WriteLine("Press Ctrl+C to stop.");

            session.Source.Process();
            return 0;
        }
        catch (UnauthorizedAccessException)
        {
            Console.Error.WriteLine("Access denied. Run from an elevated Administrator console.");
            return 5;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Collector failed: {ex.Message}");
            return 1;
        }
    }

    private static string GetOutputPath(string[] args)
    {
        if (args.Length == 0)
            return Path.Combine("out", $"kdasa-{DateTime.UtcNow:yyyyMMdd-HHmmss}.jsonl");

        if (args.Length == 2 && (args[0] == "--output" || args[0] == "-o"))
            return args[1];

        throw new ArgumentException("Usage: KdasaCollector [--output <path>]");
    }

    private static void Write(StreamWriter writer, EventRecord record)
    {
        writer.WriteLine(JsonSerializer.Serialize(record));
        writer.Flush();

        Console.WriteLine(
            $"{record.Timestamp:O} {record.Type,-12} PID={record.Pid,-6} TID={record.Tid,-6} {record.ProcessName}");
    }

    private sealed record EventRecord(
        string Type,
        DateTime Timestamp,
        int Pid,
        int Tid,
        string ProcessName,
        Dictionary<string, object?> Details);
}
