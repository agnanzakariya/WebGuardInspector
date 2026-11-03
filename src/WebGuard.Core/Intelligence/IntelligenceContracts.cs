using WebGuard.Core.Detection;
using WebGuard.Core.Findings;

namespace WebGuard.Core.Intelligence;

public sealed record IntelligenceSourceInfo(string Id, string DisplayName, string Purpose, string PlannedPhase, bool SendsDataExternally);

public sealed record PackageCoordinate(string Ecosystem, string Name, string Version);

public sealed record VulnerabilityRecord(
    string Id,
    IReadOnlyList<string> Aliases,
    string Summary,
    Severity Severity,
    IReadOnlyList<string> FixedVersions,
    bool KnownExploited,
    string SourceId,
    DateTimeOffset RetrievedAtUtc);

public sealed record MalwareHashVerdict(string Sha256, bool IsKnownMalicious, string? Family, string SourceId, DateTimeOffset RetrievedAtUtc);

/// <summary>Package vulnerability lookup (OSV.dev, GitHub Advisory, CISA KEV). Sends only package coordinates, never source code.</summary>
public interface IVulnerabilityIntelligence
{
    IntelligenceSourceInfo Source { get; }
    Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<VulnerabilityRecord>> LookupAsync(PackageCoordinate package, CancellationToken cancellationToken);
}

/// <summary>Malware hash lookup (MalwareBazaar, ThreatFox). Sends only SHA-256 values, and only with user consent.</summary>
public interface IMalwareHashIntelligence
{
    IntelligenceSourceInfo Source { get; }
    Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken);
    Task<MalwareHashVerdict?> LookupAsync(string sha256, CancellationToken cancellationToken);
}

/// <summary>Local cache with source and retrieval time, so lookups work offline and are auditable.</summary>
public interface IIntelligenceCache
{
    Task<T?> GetAsync<T>(string key, TimeSpan maxAge, CancellationToken cancellationToken) where T : class;
    Task SetAsync<T>(string key, T value, string sourceId, CancellationToken cancellationToken) where T : class;
}
