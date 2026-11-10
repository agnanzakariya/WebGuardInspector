using WebGuard.Core.Scanning;

namespace WebGuard.Core.Reporting;

public interface IReportExporter
{
    string FormatName { get; }
    string FileExtension { get; }
    Task ExportAsync(ScanReport report, Stream destination, CancellationToken cancellationToken);
}

/// <summary>A report of a whole Scan History session: the scan plus what was done with it afterwards.</summary>
public interface ISessionReportExporter
{
    string FormatName { get; }
    string FileExtension { get; }
    Task ExportAsync(ScanReport report, IReadOnlyList<SessionActivity> activities, Stream destination, CancellationToken cancellationToken);
}
