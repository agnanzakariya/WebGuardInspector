using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Scanning;

namespace WebGuard.Core.Knowledge;

public sealed record KnowledgeSearchHit(Guid FindingId, string Fingerprint, string Title, double Similarity, ValidationStatus Status, bool IsVerified);

public sealed record ValidationRecord(Guid FindingId, ValidationStatus Status, string Reviewer, string? Note, DateTimeOffset RecordedAtUtc);

public sealed record FindingOccurrence(Guid ScanId, string Fingerprint, SourceLocation Location, DateTimeOffset SeenAtUtc);

/// <summary>Security Second Brain (PostgreSQL + pgvector in Phase 4).</summary>
public interface ISecondBrainRepository
{
    Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken);
    Task SaveScanAsync(ScanReport report, CancellationToken cancellationToken);
    Task SaveFindingAsync(SecurityFinding finding, CancellationToken cancellationToken);
    Task RecordValidationAsync(ValidationRecord record, CancellationToken cancellationToken);
    Task<IReadOnlyList<FindingOccurrence>> GetOccurrencesAsync(string fingerprint, CancellationToken cancellationToken);
    Task<IReadOnlyList<KnowledgeSearchHit>> SearchSimilarAsync(string query, int take, CancellationToken cancellationToken);
}

/// <summary>Produces embeddings for semantic search (local Ollama model in Phase 4).</summary>
public interface ITextEmbeddingService
{
    int Dimensions { get; }
    Task<float[]> EmbedAsync(string text, CancellationToken cancellationToken);
}
