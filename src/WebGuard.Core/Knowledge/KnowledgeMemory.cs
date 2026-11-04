using WebGuard.Core.AI;
using WebGuard.Core.Findings;
using WebGuard.Core.Fixing;

namespace WebGuard.Core.Knowledge;

/// <summary>A finding recorded earlier in a file with this exact content (SHA-256), with its current human verdict.</summary>
public sealed record KnownFileFinding(
    string Sha256,
    string Fingerprint,
    string EngineId,
    string RuleId,
    int StartLine,
    string Title,
    FindingCategory Category,
    Severity Severity,
    ValidationStatus Status,
    string? Project,
    string RelativePath)
{
    /// <summary>A person gave a verdict (not just New / NeedsReview).</summary>
    public bool IsVerified => Status is not (ValidationStatus.New or ValidationStatus.NeedsReview);
}

/// <summary>A fix a person reviewed and applied. Its edits are tried on other files with the same rule.</summary>
public sealed record RememberedFix(
    string EngineId,
    string RuleId,
    string Fingerprint,
    string Title,
    string Explanation,
    IReadOnlyList<CodeEdit> Edits,
    string? FollowUpCommand,
    string Model,
    string? Project,
    string RelativePath,
    DateTimeOffset AppliedAtUtc);

/// <summary>An AI analysis kept for reuse: for the same finding, or the same rule and line of an identical file.</summary>
public sealed record RememberedAnalysis(
    string Fingerprint,
    string? Sha256,
    string EngineId,
    string RuleId,
    int StartLine,
    string? Project,
    string RelativePath,
    AiAnalysis Analysis);

/// <summary>
/// The Second Brain as first source of knowledge: what identical files were judged to be, which fixes were applied, and
/// which analyses exist, so scans, the AI Analyst and Fixing can reuse them instead of asking an engine or a model again.
/// </summary>
public interface IKnowledgeMemory
{
    /// <summary>Findings recorded for files with these SHA-256 values (any project or path), with current verdicts.</summary>
    Task<IReadOnlyList<KnownFileFinding>> GetKnownFindingsAsync(IReadOnlyCollection<string> sha256, CancellationToken cancellationToken);

    /// <summary>Records a fix after a person applied it.</summary>
    Task RememberFixAsync(SecurityFinding finding, FixProposal proposal, string? project, CancellationToken cancellationToken);

    /// <summary>Applied fixes for this rule, newest first.</summary>
    Task<IReadOnlyList<RememberedFix>> GetRememberedFixesAsync(string engineId, string ruleId, CancellationToken cancellationToken);

    Task RememberAnalysisAsync(SecurityFinding finding, string? fileSha256, AiAnalysis analysis, string? project, CancellationToken cancellationToken);

    /// <summary>The newest analysis of this finding, else of the same rule and line in an identical file; null when none.</summary>
    Task<RememberedAnalysis?> FindAnalysisAsync(SecurityFinding finding, string? fileSha256, CancellationToken cancellationToken);
}

/// <summary>Turns earlier human verdicts into context for an AI prompt.</summary>
public static class PriorKnowledge
{
    /// <summary>Verified hits (other findings) worth showing a model, best first.</summary>
    public static IReadOnlyList<KnowledgeSearchHit> Select(IEnumerable<KnowledgeSearchHit> hits, string fingerprint, int take = 3, double minSimilarity = 0.35) =>
        hits.Where(h => h.IsVerified && h.Similarity >= minSimilarity && h.Fingerprint != fingerprint)
            .OrderByDescending(h => h.Similarity)
            .Take(take)
            .ToArray();

    /// <summary>Search text for a finding: title, rule and category carry the meaning; paths do not.</summary>
    public static string Query(SecurityFinding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        return $"{finding.Title} {finding.RuleId} {finding.Category}";
    }

    /// <summary>Prompt section listing earlier verdicts; empty when there are none.</summary>
    public static string Describe(IReadOnlyList<KnowledgeSearchHit>? hits)
    {
        if (hits is null || hits.Count == 0) return string.Empty;
        var lines = hits.Select(h =>
            $"- [{h.Status}] {SourceRedactor.Redact(h.Title)}{(h.Project is null ? string.Empty : " (project " + h.Project + ")")}: {SourceRedactor.Redact(h.Snippet)}");
        return "PRIOR VERDICTS FROM THE SECOND BRAIN (similar findings a person already judged; use them as hints, they may not apply here)\n" +
               string.Join('\n', lines) + "\n";
    }
}
