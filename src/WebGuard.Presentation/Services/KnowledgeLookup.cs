using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Knowledge;
using WebGuard.Core.Scanning;

namespace WebGuard.Presentation.Services;

/// <summary>Second-Brain-first helpers shared by the AI Analyst and Fixing pages. Problems never block the AI.</summary>
internal static class KnowledgeLookup
{
    /// <summary>SHA-256 of the finding's file in this scan, if it was hashed.</summary>
    public static string? FileSha(ScanReport? report, SecurityFinding finding)
    {
        if (report is null) return null;
        var path = finding.Location.RelativePath.Replace('\\', '/');
        return report.Files.FirstOrDefault(f => string.Equals(f.RelativePath.Replace('\\', '/'), path, StringComparison.OrdinalIgnoreCase))?.Sha256;
    }

    /// <summary>The memory when the Second Brain is configured and "Second Brain first" is on; else null.</summary>
    public static async Task<IKnowledgeMemory?> MemoryAsync(ISecondBrainRepository? brain, SettingsService? settings, CancellationToken cancellationToken)
    {
        if (brain is not IKnowledgeMemory memory || settings?.Current.SecondBrainFirst != true) return null;
        try
        {
            return (await brain.GetStatusAsync(cancellationToken).ConfigureAwait(true)).Availability == EngineAvailability.Ready ? memory : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Earlier human verdicts on similar findings, as a prompt section; null when there are none.</summary>
    public static async Task<string?> PriorKnowledgeAsync(ISecondBrainRepository brain, SecurityFinding finding, CancellationToken cancellationToken)
    {
        try
        {
            var hits = await brain.SearchSimilarAsync(PriorKnowledge.Query(finding), 10, cancellationToken).ConfigureAwait(true);
            var text = PriorKnowledge.Describe(PriorKnowledge.Select(hits, finding.Fingerprint));
            return text.Length == 0 ? null : text;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or HttpRequestException)
        {
            return null;
        }
    }
}
