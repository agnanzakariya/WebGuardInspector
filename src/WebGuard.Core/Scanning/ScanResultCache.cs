using WebGuard.Core.Findings;

namespace WebGuard.Core.Scanning;

/// <summary>Findings of one engine for every file of the previous scan, valid while <see cref="Stamp"/> is unchanged.</summary>
public sealed record EngineResultCache(string Stamp, IReadOnlyList<SecurityFinding> Findings);

/// <summary>
/// What the previous scan of a folder saw: each file's identity (SHA-256, or size and time when not hashed) and the
/// findings of each engine that completed without warnings. Used to skip unchanged files on the next scan.
/// </summary>
public sealed record ScanResultCache(
    string RootFolder,
    IReadOnlyDictionary<string, string> Files,
    IReadOnlyDictionary<string, EngineResultCache> Engines);

/// <summary>Stores <see cref="ScanResultCache"/> per scanned folder. Failures are never fatal: the scan just runs in full.</summary>
public interface IScanResultCacheStore
{
    Task<ScanResultCache?> LoadAsync(string rootFolder, CancellationToken cancellationToken);
    Task SaveAsync(ScanResultCache cache, CancellationToken cancellationToken);

    /// <summary>Forgets every cached result (Settings → "Clear scan cache").</summary>
    void Clear();
}
