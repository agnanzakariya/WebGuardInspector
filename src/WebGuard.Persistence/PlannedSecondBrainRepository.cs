using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Knowledge;
using WebGuard.Core.Scanning;

namespace WebGuard.Persistence;

/// <summary>PostgreSQL + pgvector Second Brain — Phase 4 placeholder. Stores nothing.</summary>
public sealed class PlannedSecondBrainRepository : ISecondBrainRepository
{
    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
        Task.FromResult(EngineStatus.Planned("Phase 4"));

    public Task SaveScanAsync(ScanReport report, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task SaveFindingAsync(SecurityFinding finding, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task RecordValidationAsync(ValidationRecord record, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task<IReadOnlyList<FindingOccurrence>> GetOccurrencesAsync(string fingerprint, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<FindingOccurrence>>(Array.Empty<FindingOccurrence>());

    public Task<IReadOnlyList<KnowledgeSearchHit>> SearchSimilarAsync(string query, int take, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<KnowledgeSearchHit>>(Array.Empty<KnowledgeSearchHit>());
}
