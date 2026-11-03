using WebGuard.Core.AI;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Knowledge;
using WebGuard.Core.Scanning;

namespace WebGuard.Persistence;

/// <summary>Second Brain that stores nothing, used when no vault is configured and in tests.</summary>
public sealed class PlannedSecondBrainRepository : ISecondBrainRepository
{
    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new EngineStatus(EngineAvailability.Disabled, null, null, "No Second Brain vault configured."));

    public Task<KnowledgeStatistics> GetStatisticsAsync(CancellationToken cancellationToken) => Task.FromResult(new KnowledgeStatistics(0, 0, 0, 0));

    public Task SaveScanAsync(ScanReport report, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task SaveFindingAsync(SecurityFinding finding, string? project, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task SaveAnalysisAsync(SecurityFinding finding, AiAnalysis analysis, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task RecordValidationAsync(ValidationRecord record, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task<IReadOnlyDictionary<string, ValidationStatus>> GetValidationStatusesAsync(IEnumerable<string> fingerprints, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyDictionary<string, ValidationStatus>>(new Dictionary<string, ValidationStatus>());

    public Task<IReadOnlyList<FindingOccurrence>> GetOccurrencesAsync(string fingerprint, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<FindingOccurrence>>(Array.Empty<FindingOccurrence>());

    public Task<IReadOnlyList<KnowledgeSearchHit>> SearchSimilarAsync(string query, int take, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<KnowledgeSearchHit>>(Array.Empty<KnowledgeSearchHit>());

    public Uri? GetNoteUri(string? notePath) => null;

    public Uri? GetFindingNoteUri(string fingerprint) => null;
}
