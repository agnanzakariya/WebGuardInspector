using System.Text.Encodings.Web;
using System.Text.Json;
using WebGuard.Core.Reporting;
using WebGuard.Core.Scanning;

namespace WebGuard.Scanner;

public sealed class JsonReportExporter : IReportExporter
{
    public static JsonSerializerOptions SerializerOptions { get; } = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public string FormatName => "JSON";
    public string FileExtension => ".json";

    public Task ExportAsync(ScanReport report, Stream destination, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(destination);
        return JsonSerializer.SerializeAsync(destination, report, SerializerOptions, cancellationToken);
    }
}
