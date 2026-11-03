using WebGuard.Core.Scanning;

namespace WebGuard.Core.Reporting;

public interface IReportExporter
{
    string FormatName { get; }
    string FileExtension { get; }
    Task ExportAsync(ScanReport report, Stream destination, CancellationToken cancellationToken);
}
