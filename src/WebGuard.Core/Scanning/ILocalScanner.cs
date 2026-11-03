namespace WebGuard.Core.Scanning;

/// <summary>Read-only inventory of a user-selected local folder. Never executes or uploads files.</summary>
public interface ILocalScanner
{
    Task<ScanReport> ScanAsync(
        string folder,
        ScanOptions options,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken);
}

/// <summary>Stores completed scans for the Scan History page. v0.2 keeps them in memory; Phase 4 moves this to PostgreSQL.</summary>
public interface IScanHistoryStore
{
    Task AddAsync(ScanReport report, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ScanReport>> GetRecentAsync(int take, CancellationToken cancellationToken = default);
}
