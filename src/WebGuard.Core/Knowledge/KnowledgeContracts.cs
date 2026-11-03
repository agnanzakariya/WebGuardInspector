using WebGuard.Core.AI;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Scanning;

namespace WebGuard.Core.Knowledge;

/// <summary>A knowledge note that matched a search, with the score that ranked it.</summary>
/// <param name="NotePath">Path of the note relative to the knowledge store (e.g. an Obsidian vault).</param>
/// <param name="Snippet">Short excerpt explaining why it matched.</param>
/// <param name="Project">Project the finding was seen in, when known.</param>
public sealed record KnowledgeSearchHit(
    string Fingerprint,
    string Title,
    double Similarity,
    ValidationStatus Status,
    bool IsVerified,
    string NotePath,
    string Snippet,
    Severity Severity,
    string? Project);

/// <summary>A person's verdict on a finding, keyed by its fingerprint so it survives across scans.</summary>
public sealed record ValidationRecord(string Fingerprint, ValidationStatus Status, string Reviewer, string? Note, DateTimeOffset RecordedAtUtc);

public sealed record FindingOccurrence(Guid ScanId, string Fingerprint, SourceLocation Location, DateTimeOffset SeenAtUtc);

/// <summary>Counts shown on the Second Brain page.</summary>
public sealed record KnowledgeStatistics(int Projects, int Scans, int Findings, int Validated);

/// <summary>
/// Security Second Brain: every scan (clean or not), every finding, AI analysis and human verdict, kept as reusable
/// knowledge. Implemented as Markdown notes in an Obsidian vault.
/// </summary>
public interface ISecondBrainRepository
{
    Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken);
    Task<KnowledgeStatistics> GetStatisticsAsync(CancellationToken cancellationToken);

    /// <summary>Records the scan, its project and every finding (occurrence + current details).</summary>
    Task SaveScanAsync(ScanReport report, CancellationToken cancellationToken);

    /// <summary>Records one finding on its own (e.g. reported by an MCP client) without a scan.</summary>
    Task SaveFindingAsync(SecurityFinding finding, string? project, CancellationToken cancellationToken);

    /// <summary>Appends an AI analysis (an unverified hypothesis) to the finding's knowledge.</summary>
    Task SaveAnalysisAsync(SecurityFinding finding, AiAnalysis analysis, CancellationToken cancellationToken);

    Task RecordValidationAsync(ValidationRecord record, CancellationToken cancellationToken);

    /// <summary>Human verdicts already recorded for these fingerprints (only those with a note).</summary>
    Task<IReadOnlyDictionary<string, ValidationStatus>> GetValidationStatusesAsync(IEnumerable<string> fingerprints, CancellationToken cancellationToken);

    Task<IReadOnlyList<FindingOccurrence>> GetOccurrencesAsync(string fingerprint, CancellationToken cancellationToken);
    Task<IReadOnlyList<KnowledgeSearchHit>> SearchSimilarAsync(string query, int take, CancellationToken cancellationToken);

    /// <summary>Link that opens the store (null path) or one of its notes in the note app, e.g. obsidian://open?path=…</summary>
    Uri? GetNoteUri(string? notePath);

    /// <summary>Link to the note of a finding, or null when it has not been recorded.</summary>
    Uri? GetFindingNoteUri(string fingerprint);
}

/// <summary>Produces embeddings for semantic search (a local embedding model such as nomic-embed-text).</summary>
public interface ITextEmbeddingService
{
    string ModelId { get; }
    Task<bool> IsAvailableAsync(CancellationToken cancellationToken);

    /// <summary>Embeds documents (<paramref name="isQuery"/> false) or a search query (true); models may prefix them differently.</summary>
    Task<IReadOnlyList<float[]>> EmbedAsync(IReadOnlyList<string> texts, bool isQuery, CancellationToken cancellationToken);
}
