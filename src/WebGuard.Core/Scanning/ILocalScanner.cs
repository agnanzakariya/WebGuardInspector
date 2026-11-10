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

/// <summary>
/// Stores scan sessions for the Scan History page: the scan report plus everything done with it afterwards
/// (verdicts, AI analyses, fixes, exports), newest first.
/// </summary>
public interface IScanHistoryStore
{
    Task AddAsync(ScanReport report, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ScanReport>> GetRecentAsync(int take, CancellationToken cancellationToken = default);

    /// <summary>Adds an activity to the session of <paramref name="scanId"/>; ignored when that session is not stored.</summary>
    Task AppendActivityAsync(Guid scanId, SessionActivity activity, CancellationToken cancellationToken = default);

    /// <summary>Activities of a session in the order they happened.</summary>
    Task<IReadOnlyList<SessionActivity>> GetActivitiesAsync(Guid scanId, CancellationToken cancellationToken = default);
}
