using WebGuard.Core.Detection;

namespace WebGuard.Core.Findings;

/// <summary>Outcome of one enrichment pass: the (possibly updated) findings and how many were changed.</summary>
public sealed record EnrichmentResult(IReadOnlyList<SecurityFinding> Findings, int ChangedCount, string Message);

/// <summary>
/// Adds context to findings after all engines have run (e.g. CISA KEV "known exploited" status) without producing
/// findings of its own. Must keep each finding's fingerprint, so its identity across scans does not change.
/// </summary>
public interface IFindingEnricher
{
    SecurityEngineInfo Info { get; }

    Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken);

    Task<EnrichmentResult> EnrichAsync(IReadOnlyList<SecurityFinding> findings, CancellationToken cancellationToken);
}
