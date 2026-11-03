using WebGuard.Core.Detection;
using WebGuard.Core.Intelligence;

namespace WebGuard.Intelligence;

/// <summary>OSV.dev / GitHub Advisory / CISA KEV lookup — Phase 2 placeholder. Performs no network calls.</summary>
public sealed class PlannedVulnerabilityIntelligence : IVulnerabilityIntelligence
{
    public IntelligenceSourceInfo Source { get; } = new("osv", "OSV.dev + GitHub Advisory + CISA KEV",
        "Package vulnerabilities, GHSA/CVE aliases, known exploited flag", "Phase 2", SendsDataExternally: true);

    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
        Task.FromResult(EngineStatus.Planned(Source.PlannedPhase));

    public Task<IReadOnlyList<VulnerabilityRecord>> LookupAsync(PackageCoordinate package, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<VulnerabilityRecord>>(Array.Empty<VulnerabilityRecord>());
}

/// <summary>MalwareBazaar / ThreatFox hash lookup — Phase 2 placeholder. Performs no network calls.</summary>
public sealed class PlannedMalwareHashIntelligence : IMalwareHashIntelligence
{
    public IntelligenceSourceInfo Source { get; } = new("malwarebazaar", "MalwareBazaar + ThreatFox",
        "SHA-256 malware verdicts and IOCs (hash only, with consent)", "Phase 2", SendsDataExternally: true);

    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
        Task.FromResult(EngineStatus.Planned(Source.PlannedPhase));

    public Task<MalwareHashVerdict?> LookupAsync(string sha256, CancellationToken cancellationToken) =>
        Task.FromResult<MalwareHashVerdict?>(null);
}
