using System.Text.Json;
using WebGuard.Core.AI;
using WebGuard.Core.Findings;
using WebGuard.Core.Fixing;
using WebGuard.Core.Knowledge;
using WebGuard.Core.Scanning;

namespace WebGuard.Persistence;

/// <summary>
/// Reusable knowledge kept next to the notes in <c>.webguard/</c>: which findings were seen in which file contents
/// (by SHA-256), the fixes a person applied, and AI analyses. Verdicts are always read from the notes, so a status
/// changed in Obsidian is used too.
/// </summary>
public sealed partial class ObsidianSecondBrain : IKnowledgeMemory
{
    private const string KnownFilesIndex = "known-files.json";
    private const string FixesIndex = "fixes.json";
    private const string AnalysesIndex = "analyses.json";
    private const int MaxEntriesPerFile = 25;
    private const int MaxFixes = 1000;
    private const int MaxAnalyses = 2000;

    private sealed record KnownFileEntry(string Fingerprint, string EngineId, string RuleId, int StartLine, string Title,
        FindingCategory Category, Severity Severity, string? Project, string RelativePath);

    public async Task<IReadOnlyList<KnownFileFinding>> GetKnownFindingsAsync(IReadOnlyCollection<string> sha256, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sha256);
        if (sha256.Count == 0 || !TryVault(out var vault)) return [];
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var index = ReadIndex<Dictionary<string, List<KnownFileEntry>>>(vault, KnownFilesIndex) ?? [];
            var matches = sha256.Distinct(StringComparer.OrdinalIgnoreCase)
                .SelectMany(h => index.TryGetValue(h.ToLowerInvariant(), out var entries) ? entries.Select(e => (Sha: h.ToLowerInvariant(), Entry: e)) : [])
                .ToList();
            var statuses = new Dictionary<string, ValidationStatus>(StringComparer.Ordinal);
            foreach (var fingerprint in matches.Select(m => m.Entry.Fingerprint).Distinct(StringComparer.Ordinal))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (FindFindingNote(vault, fingerprint) is { } path && ParseStatus(MarkdownNote.Parse(File.ReadAllText(path)).Get("status")) is { } s)
                    statuses[fingerprint] = s;
            }
            return matches
                .Select(m => new KnownFileFinding(m.Sha, m.Entry.Fingerprint, m.Entry.EngineId, m.Entry.RuleId, m.Entry.StartLine, m.Entry.Title,
                    m.Entry.Category, m.Entry.Severity, statuses.TryGetValue(m.Entry.Fingerprint, out var st) ? st : ValidationStatus.New,
                    m.Entry.Project, m.Entry.RelativePath))
                .ToArray();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task RememberFixAsync(SecurityFinding finding, FixProposal proposal, string? project, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(finding);
        ArgumentNullException.ThrowIfNull(proposal);
        if (proposal.Edits.Count == 0) return;
        var vault = RequireVault();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var fixes = ReadIndex<List<RememberedFix>>(vault, FixesIndex) ?? [];
            fixes.RemoveAll(f => f.Fingerprint == finding.Fingerprint);
            fixes.Insert(0, new RememberedFix(finding.EngineId, finding.RuleId, finding.Fingerprint, Redact(finding.Title), Redact(proposal.Explanation),
                proposal.Edits, proposal.FollowUpCommand, proposal.Model, project, finding.Location.RelativePath, _time.GetUtcNow()));
            WriteIndex(vault, FixesIndex, fixes.Take(MaxFixes).ToList());
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<RememberedFix>> GetRememberedFixesAsync(string engineId, string ruleId, CancellationToken cancellationToken)
    {
        if (!TryVault(out var vault)) return [];
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return (ReadIndex<List<RememberedFix>>(vault, FixesIndex) ?? [])
                .Where(f => f.EngineId == engineId && f.RuleId == ruleId)
                .ToArray();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task RememberAnalysisAsync(SecurityFinding finding, string? fileSha256, AiAnalysis analysis, string? project, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(finding);
        ArgumentNullException.ThrowIfNull(analysis);
        var vault = RequireVault();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var analyses = ReadIndex<List<RememberedAnalysis>>(vault, AnalysesIndex) ?? [];
            analyses.RemoveAll(a => a.Fingerprint == finding.Fingerprint);
            var redacted = analysis with
            {
                Summary = Redact(analysis.Summary),
                WhyRisky = Redact(analysis.WhyRisky),
                ProposedRemediation = analysis.ProposedRemediation is null ? null : Redact(analysis.ProposedRemediation),
            };
            analyses.Insert(0, new RememberedAnalysis(finding.Fingerprint, fileSha256?.ToLowerInvariant(), finding.EngineId, finding.RuleId,
                finding.Location.StartLine, project, finding.Location.RelativePath, redacted));
            WriteIndex(vault, AnalysesIndex, analyses.Take(MaxAnalyses).ToList());
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<RememberedAnalysis?> FindAnalysisAsync(SecurityFinding finding, string? fileSha256, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(finding);
        if (!TryVault(out var vault)) return null;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var analyses = ReadIndex<List<RememberedAnalysis>>(vault, AnalysesIndex) ?? [];
            return analyses.FirstOrDefault(a => a.Fingerprint == finding.Fingerprint)
                   ?? (fileSha256 is null
                       ? null
                       : analyses.FirstOrDefault(a => string.Equals(a.Sha256, fileSha256, StringComparison.OrdinalIgnoreCase) &&
                                                      a.EngineId == finding.EngineId && a.RuleId == finding.RuleId && a.StartLine == finding.Location.StartLine));
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Called by <see cref="SaveScanAsync"/> (inside the gate): remembers which findings each file content had.</summary>
    private static void UpdateKnownFiles(string vault, string project, ScanReport report)
    {
        if (report.Findings.Count == 0) return;
        var hashes = report.Files
            .Where(f => f.Sha256 is not null)
            .GroupBy(f => f.RelativePath.Replace('\\', '/'), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Sha256!, StringComparer.OrdinalIgnoreCase);
        var index = ReadIndex<Dictionary<string, List<KnownFileEntry>>>(vault, KnownFilesIndex) ?? [];
        var changed = false;
        foreach (var f in report.Findings)
        {
            if (!hashes.TryGetValue(f.Location.RelativePath.Replace('\\', '/'), out var sha)) continue;
            if (!index.TryGetValue(sha, out var entries)) index[sha] = entries = [];
            if (entries.Any(e => e.Fingerprint == f.Fingerprint)) continue;
            entries.Insert(0, new KnownFileEntry(f.Fingerprint, f.EngineId, f.RuleId, f.Location.StartLine, Redact(f.Title), f.Category, f.Severity,
                project, f.Location.RelativePath));
            if (entries.Count > MaxEntriesPerFile) entries.RemoveRange(MaxEntriesPerFile, entries.Count - MaxEntriesPerFile);
            changed = true;
        }
        if (changed) WriteIndex(vault, KnownFilesIndex, index);
    }

    private static T? ReadIndex<T>(string vault, string name) where T : class
    {
        var path = Path.Combine(vault, IndexFolder, name);
        try
        {
            return File.Exists(path) ? JsonSerializer.Deserialize<T>(File.ReadAllText(path), IndexJson) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return null;
        }
    }

    private static void WriteIndex<T>(string vault, string name, T value)
    {
        var path = Path.Combine(vault, IndexFolder, name);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var temp = path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(value, IndexJson));
            File.Move(temp, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // Knowledge indexes are rebuilt by later scans; the notes are the record.
        }
    }
}
