using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using WebGuard.Core.AI;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Knowledge;
using WebGuard.Core.Scanning;

namespace WebGuard.Persistence;

/// <summary>Where the Second Brain lives. Read on every call so Settings changes apply without a restart.</summary>
public sealed record SecondBrainSettings(string? VaultPath);

/// <summary>
/// Security Second Brain kept as Markdown in an Obsidian vault:
/// <c>Dashboard.md</c>, <c>Projects/</c> (one note per scanned folder), <c>Scans/</c> (one note per scan, clean or not),
/// <c>Findings/</c> (one note per unique finding fingerprint, with occurrences, AI analyses and verdicts) and
/// <c>Rules/</c> (what each rule has found). Notes use properties and wiki links so Obsidian's search, graph and
/// Bases/Dataview work on them. WebGuard only rewrites its own properties and <c>webguard:</c> blocks; the
/// <c>status</c> property and everything a person writes are preserved. Secrets are redacted before anything is written.
/// </summary>
public sealed partial class ObsidianSecondBrain(Func<SecondBrainSettings> settings, ITextEmbeddingService? embeddings = null, TimeProvider? timeProvider = null)
    : ISecondBrainRepository, IDisposable
{
    public const string ProjectsFolder = "Projects";
    public const string ScansFolder = "Scans";
    public const string FindingsFolder = "Findings";
    public const string RulesFolder = "Rules";
    public const string DashboardNote = "Dashboard.md";
    private const string IndexFolder = ".webguard";

    private static readonly JsonSerializerOptions IndexJson = new() { WriteIndented = false };
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    public void Dispose() => _gate.Dispose();

    // ---- Status -------------------------------------------------------------------------------------------------

    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        var path = settings().VaultPath;
        if (string.IsNullOrWhiteSpace(path))
            return Task.FromResult(new EngineStatus(EngineAvailability.Disabled, null, null, "Choose an Obsidian vault folder in Settings → Second Brain."));
        if (!Directory.Exists(path))
            return Task.FromResult(new EngineStatus(EngineAvailability.Error, null, path, "Vault folder not found: " + path));
        var stats = CountNotes(path);
        var vault = Directory.Exists(Path.Combine(path, ".obsidian")) ? "Obsidian vault" : "Folder (open it in Obsidian as a vault)";
        return Task.FromResult(new EngineStatus(EngineAvailability.Ready, null, path,
            $"{vault} '{Path.GetFileName(path.TrimEnd('\\', '/'))}': {stats.Projects} projects, {stats.Scans} scans, {stats.Findings} findings."));
    }

    public Task<KnowledgeStatistics> GetStatisticsAsync(CancellationToken cancellationToken) =>
        Task.FromResult(TryVault(out var vault) ? CountNotes(vault) : new KnowledgeStatistics(0, 0, 0, 0));

    // ---- Recording ----------------------------------------------------------------------------------------------

    public async Task SaveScanAsync(ScanReport report, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(report);
        var vault = RequireVault();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var project = ProjectName(vault, report.RootFolder);
            var started = Local(report.StartedAtUtc);
            var scanName = $"{started:yyyy-MM-dd HHmmss} {project}";
            var scanLink = $"{ScansFolder}/{scanName}";

            var findingLinks = new List<(SecurityFinding Finding, string Link)>();
            foreach (var finding in report.Findings)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var link = UpsertFinding(vault, finding, project, (scanLink, report.ScanId, report.StartedAtUtc));
                findingLinks.Add((finding, link));
                UpsertRule(vault, finding, link);
            }

            WriteNote(Path.Combine(vault, ScansFolder, scanName + ".md"), BuildScanNote(report, project, findingLinks));
            MarkAbsent(vault, project, findingLinks.Select(f => f.Link), scanLink, report);
            UpdateProject(vault, project, report, scanLink, findingLinks);
            UpdateDashboard(vault);
            UpdateKnownFiles(vault, project, report);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveFindingAsync(SecurityFinding finding, string? project, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(finding);
        var vault = RequireVault();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var link = UpsertFinding(vault, finding, project, null);
            UpsertRule(vault, finding, link);
            UpdateDashboard(vault);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveAnalysisAsync(SecurityFinding finding, AiAnalysis analysis, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(finding);
        ArgumentNullException.ThrowIfNull(analysis);
        var vault = RequireVault();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var path = FindFindingNote(vault, finding.Fingerprint) ?? Path.Combine(vault, UpsertFinding(vault, finding, null, null) + ".md");
            var note = MarkdownNote.Parse(File.ReadAllText(path));
            var entry = new StringBuilder()
                .Append(CultureInfo.InvariantCulture, $"### {Local(analysis.CreatedAtUtc):yyyy-MM-dd HH:mm} · {analysis.Model} · {analysis.Confidence} confidence\n")
                .Append("> [!warning] AI hypothesis — not verified\n> Validate before acting; nothing was changed in the project.\n\n")
                .Append("**Summary:** ").Append(Redact(analysis.Summary)).Append("\n\n");
            if (!string.IsNullOrWhiteSpace(analysis.WhyRisky)) entry.Append("**Why it matters:** ").Append(Redact(analysis.WhyRisky)).Append("\n\n");
            if (!string.IsNullOrWhiteSpace(analysis.ProposedRemediation))
                entry.Append("**Proposed fix (review before applying):**\n\n").Append(Redact(analysis.ProposedRemediation)).Append('\n');
            var previous = note.GetBlock("ai");
            note.SetBlock("ai", (IsPlaceholder(previous) ? string.Empty : previous + "\n\n") + entry.ToString().TrimEnd());
            note.SetNumber("ai_analyses", (note.GetBlock("ai") ?? string.Empty).Split("\n### ").Length);
            WriteNote(path, note);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task RecordValidationAsync(ValidationRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        var vault = RequireVault();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var path = FindFindingNote(vault, record.Fingerprint)
                       ?? throw new InvalidOperationException("This finding is not in the Second Brain yet; scan the project first.");
            var note = MarkdownNote.Parse(File.ReadAllText(path));
            note.SetPlain("status", record.Status.ToString());
            note.SetDate("validated_at", Local(record.RecordedAtUtc));
            note.SetString("validated_by", record.Reviewer);
            var line = $"- {Local(record.RecordedAtUtc):yyyy-MM-dd HH:mm} · **{record.Status}** by {record.Reviewer}" +
                       (string.IsNullOrWhiteSpace(record.Note) ? string.Empty : " — " + Redact(record.Note));
            var previous = note.GetBlock("validation");
            note.SetBlock("validation", (IsPlaceholder(previous) ? string.Empty : previous + "\n") + line);
            WriteNote(path, note);
            UpdateDashboard(vault);
        }
        finally
        {
            _gate.Release();
        }
    }

    // ---- Reading ------------------------------------------------------------------------------------------------

    public Task<IReadOnlyDictionary<string, ValidationStatus>> GetValidationStatusesAsync(IEnumerable<string> fingerprints, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fingerprints);
        var result = new Dictionary<string, ValidationStatus>(StringComparer.Ordinal);
        if (!TryVault(out var vault)) return Task.FromResult<IReadOnlyDictionary<string, ValidationStatus>>(result);
        foreach (var fingerprint in fingerprints.Distinct(StringComparer.Ordinal))
        {
            var path = FindFindingNote(vault, fingerprint);
            if (path is not null && ParseStatus(MarkdownNote.Parse(File.ReadAllText(path)).Get("status")) is { } status)
                result[fingerprint] = status;
        }
        return Task.FromResult<IReadOnlyDictionary<string, ValidationStatus>>(result);
    }

    public Task<IReadOnlyList<FindingOccurrence>> GetOccurrencesAsync(string fingerprint, CancellationToken cancellationToken)
    {
        if (!TryVault(out var vault) || FindFindingNote(vault, fingerprint) is not { } path)
            return Task.FromResult<IReadOnlyList<FindingOccurrence>>([]);
        var block = MarkdownNote.Parse(File.ReadAllText(path)).GetBlock("occurrences") ?? string.Empty;
        var occurrences = OccurrenceLine().Matches(block).Select(m => new FindingOccurrence(
            Guid.Parse(m.Groups["scan"].Value), fingerprint, new SourceLocation(m.Groups["location"].Value.Trim(), 0, 0),
            DateTimeOffset.Parse(m.Groups["seen"].Value, CultureInfo.InvariantCulture))).ToArray();
        return Task.FromResult<IReadOnlyList<FindingOccurrence>>(occurrences);
    }

    public Uri? GetFindingNoteUri(string fingerprint) =>
        TryVault(out var vault) && FindFindingNote(vault, fingerprint) is { } path ? ObsidianUri(path) : null;

    public Uri? GetNoteUri(string? notePath)
    {
        if (!TryVault(out var vault)) return null;
        if (string.IsNullOrEmpty(notePath)) return ObsidianUri(vault);
        var full = Path.GetFullPath(Path.Combine(vault, notePath));
        return full.StartsWith(vault + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ? ObsidianUri(full) : null;
    }

    public static Uri ObsidianUri(string path) => new("obsidian://open?path=" + Uri.EscapeDataString(Path.GetFullPath(path)));

    /// <summary>
    /// Keyword search over finding notes (title, rule, description, AI analyses and personal notes), blended with
    /// semantic similarity when a local embedding model is available. Embeddings are cached in <c>.webguard/</c>.
    /// </summary>
    public async Task<IReadOnlyList<KnowledgeSearchHit>> SearchSimilarAsync(string query, int take, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(query) || !TryVault(out var vault)) return [];
        var documents = LoadFindingDocuments(vault);
        if (documents.Count == 0) return [];

        var terms = Tokens(query);
        var keyword = documents.Select(d => KeywordScore(d, terms)).ToArray();
        double[]? semantic = null;
        if (embeddings is not null && await SafeAvailableAsync(cancellationToken).ConfigureAwait(false))
            semantic = await SemanticScoresAsync(vault, documents, query, cancellationToken).ConfigureAwait(false);

        return documents
            .Select((d, i) => (Doc: d, Score: semantic is null ? keyword[i] : 0.6 * semantic[i] + 0.4 * keyword[i], Keyword: keyword[i]))
            .Where(x => x.Keyword > 0 || (semantic is not null && x.Score >= 0.45))
            .OrderByDescending(x => x.Score)
            .Take(Math.Max(1, take))
            .Select(x => new KnowledgeSearchHit(x.Doc.Fingerprint, x.Doc.Title, Math.Round(x.Score, 3), x.Doc.Status,
                x.Doc.Status is not (ValidationStatus.New or ValidationStatus.NeedsReview), x.Doc.RelativePath, Snippet(x.Doc, terms),
                x.Doc.Severity, x.Doc.Project))
            .ToArray();
    }

    // ---- Notes --------------------------------------------------------------------------------------------------

    /// <summary>Creates or updates the note of one finding and returns its link target (vault-relative path without .md).</summary>
    private string UpsertFinding(string vault, SecurityFinding finding, string? project, (string Link, Guid ScanId, DateTimeOffset Seen)? scan)
    {
        var path = FindFindingNote(vault, finding.Fingerprint);
        var isNew = path is null;
        path ??= Path.Combine(vault, FindingsFolder, $"{SafeName(finding.Title, 70)} ({Short(finding.Fingerprint)}).md");
        var note = isNew ? NewFindingNote(finding) : MarkdownNote.Parse(File.ReadAllText(path));
        var now = Local(scan?.Seen ?? _time.GetUtcNow());

        note.SetString("webguard", "finding");
        note.SetString("fingerprint", finding.Fingerprint);
        note.SetString("title", Redact(finding.Title));
        var projects = note.GetList("projects").ToList();
        if (project is not null && !projects.Contains($"[[{ProjectsFolder}/{project}]]", StringComparer.Ordinal)) projects.Add($"[[{ProjectsFolder}/{project}]]");
        note.SetList("projects", projects);
        note.SetString("engine", finding.EngineId);
        note.SetString("rule", finding.RuleId);
        note.SetPlain("category", finding.Category.ToString());
        note.SetPlain("severity", finding.Severity.ToString());
        note.SetPlain("confidence", finding.Confidence.ToString());
        note.SetPlain("origin", finding.Origin.ToString());
        note.SetString("location", finding.Location.ToString());
        note.SetList("cwe", finding.CweIds);
        note.SetList("advisories", finding.AdvisoryIds);
        note.SetPlain("known_exploited", finding.Evidence.Any(e => e.Kind == "known-exploited") ? "true" : "false");
        if (isNew || !note.Has("status")) note.SetPlain("status", finding.Status.ToString());
        if (isNew || !note.Has("first_seen")) note.SetDate("first_seen", now);
        if (scan is not null)
        {
            note.SetDate("last_seen", now);
            note.SetPlain("present", "true");
        }
        else if (isNew)
        {
            note.SetDate("last_seen", now);
        }
        note.SetList("tags", ["webguard/finding", "severity/" + finding.Severity.ToString().ToLowerInvariant(),
            "engine/" + Tag(finding.EngineId), "category/" + Tag(finding.Category.ToString())]);
        note.SetBlock("details", FindingDetails(finding));

        if (scan is { } s)
        {
            var occurrences = note.GetBlock("occurrences");
            if (IsPlaceholder(occurrences)) occurrences = string.Empty;
            if (!occurrences!.Contains($"scan:{s.ScanId:N}", StringComparison.Ordinal))
            {
                var line = $"- [[{s.Link}|{Local(s.Seen):yyyy-MM-dd HH:mm}]] · {project} · `{finding.Location}` " +
                           $"<!-- scan:{s.ScanId:N} seen:{s.Seen.UtcDateTime:O} location:{finding.Location} -->";
                occurrences = (occurrences.Length == 0 ? string.Empty : occurrences + "\n") + line;
                note.SetBlock("occurrences", occurrences);
            }
            note.SetNumber("occurrences", OccurrenceLine().Count(occurrences));
        }

        WriteNote(path, note);
        return Path.GetRelativePath(vault, path)[..^3].Replace('\\', '/');
    }

    /// <summary>
    /// Findings that were open in this project's previous scan but are missing now are marked <c>present: false</c> with a
    /// "not seen" occurrence line, so fixes and regressions are visible. Their status is left to a person.
    /// </summary>
    private void MarkAbsent(string vault, string project, IEnumerable<string> currentLinks, string scanLink, ScanReport report)
    {
        var projectPath = Path.Combine(vault, ProjectsFolder, project + ".md");
        if (!File.Exists(projectPath) || report.Engines.All(e => e.Outcome != "Completed")) return;
        var current = currentLinks.ToHashSet(StringComparer.Ordinal);
        var previous = WikiLink().Matches(MarkdownNote.Parse(File.ReadAllText(projectPath)).GetBlock("open") ?? string.Empty)
            .Select(m => m.Groups["target"].Value)
            .Where(l => l.StartsWith(FindingsFolder + "/", StringComparison.Ordinal) && !current.Contains(l))
            .Distinct(StringComparer.Ordinal)
            .ToList();
        foreach (var link in previous)
        {
            var path = Path.Combine(vault, link + ".md");
            if (!File.Exists(path)) continue;
            var note = MarkdownNote.Parse(File.ReadAllText(path));
            note.SetPlain("present", "false");
            var block = note.GetBlock("occurrences") ?? string.Empty;
            var marker = $"absent:{report.ScanId:N}";
            if (!block.Contains(marker, StringComparison.Ordinal))
            {
                note.SetBlock("occurrences", block +
                    $"\n- Not seen in [[{scanLink}|{Local(report.StartedAtUtc):yyyy-MM-dd HH:mm}]] · {project} — likely fixed; set status Fixed after review <!-- {marker} -->");
            }
            WriteNote(path, note);
        }
    }

    private static MarkdownNote NewFindingNote(SecurityFinding finding)
    {
        var body = new StringBuilder()
            .Append("# ").Append(Redact(finding.Title)).Append("\n\n")
            .Append("<!-- webguard:details -->\n<!-- /webguard:details -->\n\n")
            .Append("## Occurrences\n<!-- webguard:occurrences -->\n_Not seen in a scan yet._\n<!-- /webguard:occurrences -->\n\n")
            .Append("## AI analyses\n<!-- webguard:ai -->\n_No AI analysis yet. Use **Analyze with AI** in WebGuard._\n<!-- /webguard:ai -->\n\n")
            .Append("## Validation history\n<!-- webguard:validation -->\n_Not validated yet. Set the **status** property (New, NeedsReview, Confirmed, FalsePositive, AcceptedRisk, Fixed) here or in WebGuard._\n<!-- /webguard:validation -->\n\n")
            .Append("## My notes\n\n");
        return MarkdownNote.Create(body.ToString());
    }

    private static string FindingDetails(SecurityFinding f)
    {
        var callout = f.Severity is Severity.Critical or Severity.High ? "danger" : f.Severity == Severity.Medium ? "warning" : "note";
        var sb = new StringBuilder()
            .Append(CultureInfo.InvariantCulture, $"> [!{callout}] {f.Severity} · {f.Category} · {f.Confidence} confidence\n")
            .Append(CultureInfo.InvariantCulture, $"> `{f.Location}` — {f.EngineId} / `{f.RuleId}`\n\n")
            .Append(Redact(f.Description)).Append("\n\n");
        if (f.Evidence.Count > 0)
        {
            sb.Append("**Evidence (redacted)**\n\n");
            foreach (var e in f.Evidence) sb.Append("- ").Append(e.Summary).Append(": `").Append(Redact(e.RedactedSnippet).Replace('`', '\'')).Append("`\n");
            sb.Append('\n');
        }
        if (f.CweIds.Count + f.AdvisoryIds.Count > 0) sb.Append("**References:** ").Append(string.Join(", ", f.CweIds.Concat(f.AdvisoryIds))).Append("\n\n");
        if (!string.IsNullOrWhiteSpace(f.Remediation)) sb.Append("**Remediation:** ").Append(Redact(f.Remediation)).Append('\n');
        return sb.ToString();
    }

    private static void UpsertRule(string vault, SecurityFinding finding, string findingLink)
    {
        var path = Path.Combine(vault, RulesFolder, SafeName($"{finding.EngineId} — {finding.RuleId}", 90) + ".md");
        var note = File.Exists(path)
            ? MarkdownNote.Parse(File.ReadAllText(path))
            : MarkdownNote.Create($"# {finding.EngineId} — {finding.RuleId}\n\n## Findings\n<!-- webguard:findings -->\n<!-- /webguard:findings -->\n\n" +
                                  "## My notes\n\nHow to fix this kind of issue, known false positives, team decisions…\n");
        note.SetString("webguard", "rule");
        note.SetString("engine", finding.EngineId);
        note.SetString("rule", finding.RuleId);
        note.SetList("cwe", finding.CweIds.Union(note.GetList("cwe")).Distinct(StringComparer.Ordinal));
        note.SetList("tags", ["webguard/rule", "engine/" + Tag(finding.EngineId)]);
        var block = note.GetBlock("findings") ?? string.Empty;
        if (!block.Contains($"[[{findingLink}|", StringComparison.Ordinal))
            note.SetBlock("findings", (block.Length == 0 ? string.Empty : block + "\n") + $"- [[{findingLink}|{EscapeLink(Redact(finding.Title))}]] · {finding.Severity} · `{finding.Location}`");
        WriteNote(path, note);
    }

    private MarkdownNote BuildScanNote(ScanReport report, string project, List<(SecurityFinding Finding, string Link)> findings)
    {
        var summary = SeveritySummary.From(report.Findings);
        var enginesRan = report.Engines.Count(e => e.Outcome == "Completed");
        var result = report.Findings.Count > 0 ? "findings" : enginesRan > 0 ? "clean" : "not-analyzed";
        var note = MarkdownNote.Create(string.Empty);
        note.SetString("webguard", "scan");
        note.SetString("scan_id", report.ScanId.ToString("N"));
        note.SetString("project", $"[[{ProjectsFolder}/{project}]]");
        note.SetString("root", report.RootFolder);
        note.SetDate("started", Local(report.StartedAtUtc));
        note.SetNumber("duration_s", Math.Round(report.Duration.TotalSeconds, 1));
        note.SetPlain("result", result);
        note.SetNumber("files", report.Statistics.FileCount);
        note.SetNumber("findings", report.Findings.Count);
        note.SetNumber("critical", summary.Critical);
        note.SetNumber("high", summary.High);
        note.SetNumber("medium", summary.Medium);
        note.SetNumber("low", summary.Low);
        note.SetNumber("engines_completed", enginesRan);
        note.SetString("tool_version", report.ToolVersion);
        note.SetList("tags", ["webguard/scan", "result/" + result]);

        var sb = new StringBuilder($"# Scan {Local(report.StartedAtUtc):yyyy-MM-dd HH:mm} — {project}\n\n");
        sb.Append(result switch
        {
            "clean" => $"> [!success] Clean — no findings\n> {enginesRan} security check(s) ran on {report.Statistics.FileCount} file(s) and reported nothing.\n\n",
            "not-analyzed" => "> [!warning] Not analysed\n> No security engine completed, so this scan only inventoried and hashed the files. It does not prove the project is clean.\n\n",
            _ => $"> [!danger] {report.Findings.Count} finding(s)\n> {summary.Critical} Critical · {summary.High} High · {summary.Medium} Medium · {summary.Low} Low · {summary.Info} Info\n\n",
        });
        sb.Append(CultureInfo.InvariantCulture, $"Project: [[{ProjectsFolder}/{project}]] · Folder: `{report.RootFolder}` · Duration: {report.Duration.TotalSeconds:0.0} s · WebGuard {report.ToolVersion}\n\n");

        sb.Append("## Engines\n\n| Engine | Outcome | Version | Findings | Details |\n| --- | --- | --- | --- | --- |\n");
        foreach (var e in report.Engines)
            sb.Append(CultureInfo.InvariantCulture, $"| {e.DisplayName} | {e.Outcome} | {e.Version ?? "—"} | {e.FindingCount} | {Cell(e.Message)} |\n");

        sb.Append("\n## Findings\n\n");
        if (findings.Count == 0) sb.Append("_None._\n");
        else
        {
            sb.Append("| Severity | Finding | Location | Engine | Status |\n| --- | --- | --- | --- | --- |\n");
            foreach (var (f, link) in findings.OrderByDescending(x => x.Finding.Severity))
                sb.Append(CultureInfo.InvariantCulture, $"| {f.Severity} | [[{link}\\|{EscapeLink(Cell(Redact(f.Title)))}]] | `{f.Location}` | {f.EngineId} | {f.Status} |\n");
        }

        var st = report.Statistics;
        sb.Append(CultureInfo.InvariantCulture,
            $"\n## Inventory\n\n- Files: {st.FileCount} ({st.HashedCount} hashed, {st.SkippedCount} skipped, {st.ErrorCount} errors)\n- Size: {st.TotalBytes:N0} bytes\n- Excluded folders: {st.ExcludedDirectoryCount}\n");
        sb.Append("\n## My notes\n\n");
        return MarkdownNote.Parse(note.Render().TrimEnd('\n') + sb);
    }

    private void UpdateProject(string vault, string project, ScanReport report, string scanLink, List<(SecurityFinding Finding, string Link)> findings)
    {
        var path = Path.Combine(vault, ProjectsFolder, project + ".md");
        var note = File.Exists(path)
            ? MarkdownNote.Parse(File.ReadAllText(path))
            : MarkdownNote.Create($"# {project}\n\n## Current findings\n<!-- webguard:open -->\n<!-- /webguard:open -->\n\n" +
                                  "## Scan history\n<!-- webguard:history -->\n<!-- /webguard:history -->\n\n## My notes\n\n");
        var summary = SeveritySummary.From(report.Findings);
        var result = report.Findings.Count > 0 ? "findings" : report.Engines.Any(e => e.Outcome == "Completed") ? "clean" : "not-analyzed";
        var history = note.GetBlock("history") ?? string.Empty;
        var header = "| Date | Result | Findings | Critical | High | Medium | Low |\n| --- | --- | --- | --- | --- | --- | --- |";
        var rows = history.Split('\n').Where(l => l.StartsWith("| [[", StringComparison.Ordinal)).ToList();
        rows.Insert(0, $"| [[{scanLink}\\|{Local(report.StartedAtUtc):yyyy-MM-dd HH:mm}]] | {result} | {report.Findings.Count} | {summary.Critical} | {summary.High} | {summary.Medium} | {summary.Low} |");

        note.SetString("webguard", "project");
        note.SetString("root", report.RootFolder);
        note.SetDate("last_scan", Local(report.StartedAtUtc));
        note.SetPlain("last_result", result);
        note.SetNumber("scans", rows.Count);
        note.SetNumber("open_findings", report.Findings.Count);
        note.SetNumber("critical", summary.Critical);
        note.SetNumber("high", summary.High);
        note.SetList("tags", ["webguard/project"]);
        note.SetBlock("history", header + "\n" + string.Join('\n', rows));
        note.SetBlock("open", findings.Count == 0
            ? result == "clean" ? "> [!success] Clean in the last scan." : "> [!warning] The last scan ran no security engine."
            : string.Join('\n', findings.OrderByDescending(x => x.Finding.Severity)
                .Select(x => $"- **{x.Finding.Severity}** [[{x.Link}|{EscapeLink(Redact(x.Finding.Title))}]] · `{x.Finding.Location}` · {x.Finding.Status}")));
        WriteNote(path, note);
    }

    private void UpdateDashboard(string vault)
    {
        var path = Path.Combine(vault, DashboardNote);
        var note = File.Exists(path)
            ? MarkdownNote.Parse(File.ReadAllText(path))
            : MarkdownNote.Create("# WebGuard Second Brain\n\n<!-- webguard:dashboard -->\n<!-- /webguard:dashboard -->\n\n## My notes\n\n");
        note.SetString("webguard", "dashboard");
        note.SetList("tags", ["webguard/dashboard"]);

        var stats = CountNotes(vault);
        var sb = new StringBuilder();
        sb.Append(CultureInfo.InvariantCulture,
            $"Updated {Local(_time.GetUtcNow()):yyyy-MM-dd HH:mm} · {stats.Projects} projects · {stats.Scans} scans · {stats.Findings} findings · {stats.Validated} validated\n\n");

        sb.Append("## Projects\n\n| Project | Last scan | Result | Open findings | Critical | High |\n| --- | --- | --- | --- | --- | --- |\n");
        foreach (var p in Notes(vault, ProjectsFolder).OrderByDescending(n => n.Note.Get("last_scan"), StringComparer.Ordinal))
            sb.Append(CultureInfo.InvariantCulture,
                $"| [[{p.Link}\\|{Path.GetFileName(p.Link)}]] | {p.Note.Get("last_scan")?.Replace('T', ' ')} | {p.Note.Get("last_result")} | {p.Note.Get("open_findings")} | {p.Note.Get("critical")} | {p.Note.Get("high")} |\n");

        sb.Append("\n## Needs attention\n\nCritical and High findings that are not resolved (status New, NeedsReview or Confirmed).\n\n");
        var attention = Notes(vault, FindingsFolder)
            .Where(f => f.Note.Get("severity") is "Critical" or "High" && f.Note.Get("present") != "false" &&
                        ParseStatus(f.Note.Get("status")) is null or ValidationStatus.New or ValidationStatus.NeedsReview or ValidationStatus.Confirmed)
            .OrderBy(f => f.Note.Get("severity") == "Critical" ? 0 : 1).ThenByDescending(f => f.Note.Get("last_seen"), StringComparer.Ordinal)
            .Take(25).ToList();
        sb.Append(attention.Count == 0 ? "_Nothing open._\n" : string.Join('\n', attention.Select(f =>
            $"- **{f.Note.Get("severity")}** [[{f.Link}|{EscapeLink(f.Note.Get("title") ?? Path.GetFileName(f.Link))}]] · {f.Note.Get("status")} · last seen {f.Note.Get("last_seen")?.Replace('T', ' ')}")) + "\n");

        sb.Append("\n## Recent scans\n\n");
        var scans = Directory.Exists(Path.Combine(vault, ScansFolder))
            ? Directory.EnumerateFiles(Path.Combine(vault, ScansFolder), "*.md").OrderByDescending(Path.GetFileName, StringComparer.Ordinal).Take(15).ToList()
            : [];
        sb.Append(scans.Count == 0 ? "_No scans yet._\n" : string.Join('\n', scans.Select(s =>
        {
            var n = MarkdownNote.Parse(File.ReadAllText(s));
            return $"- [[{ScansFolder}/{Path.GetFileNameWithoutExtension(s)}]] · {n.Get("result")} · {n.Get("findings")} finding(s)";
        })) + "\n");
        note.SetBlock("dashboard", sb.ToString());
        WriteNote(path, note);
    }

    // ---- Search internals ---------------------------------------------------------------------------------------

    private sealed record FindingDocument(string RelativePath, string Fingerprint, string Title, string Rule, string Text, ValidationStatus Status, Severity Severity, string? Project);

    private static List<FindingDocument> LoadFindingDocuments(string vault) => Notes(vault, FindingsFolder)
        .Select(n => new FindingDocument(
            n.Link + ".md",
            n.Note.Get("fingerprint") ?? string.Empty,
            n.Note.Get("title") ?? Path.GetFileName(n.Link),
            n.Note.Get("rule") ?? string.Empty,
            HtmlComment().Replace(n.Note.Body, string.Empty),
            ParseStatus(n.Note.Get("status")) ?? ValidationStatus.New,
            Enum.TryParse<Severity>(n.Note.Get("severity"), out var sev) ? sev : Severity.Info,
            FirstProject(n.Note.GetList("projects"))))
        .Where(d => d.Fingerprint.Length > 0)
        .ToList();

    private static string? FirstProject(IReadOnlyList<string> projects) =>
        projects.Count == 0 ? null : projects[0].Trim('[', ']').Split('/')[^1];

    private static double KeywordScore(FindingDocument d, string[] terms)
    {
        if (terms.Length == 0) return 0;
        double score = 0;
        foreach (var t in terms)
        {
            score += 3 * Count(d.Title, t) + 2 * Count(d.Rule, t) + Math.Min(5, Count(d.Text, t));
        }
        return 1 - Math.Exp(-score / 4);
    }

    private async Task<double[]> SemanticScoresAsync(string vault, List<FindingDocument> documents, string query, CancellationToken cancellationToken)
    {
        var indexPath = Path.Combine(vault, IndexFolder, "embeddings.json");
        var index = LoadIndex(indexPath, embeddings!.ModelId);
        var texts = documents.Select(d => Truncate($"{d.Title}\n{d.Rule}\n{d.Text}", 2000)).ToArray();
        var hashes = texts.Select(t => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(t)))[..16]).ToArray();
        var stale = Enumerable.Range(0, documents.Count)
            .Where(i => !index.Entries.TryGetValue(documents[i].RelativePath, out var e) || e.Hash != hashes[i]).ToArray();
        for (var start = 0; start < stale.Length; start += 16)
        {
            var batch = stale.Skip(start).Take(16).ToArray();
            var vectors = await embeddings.EmbedAsync(batch.Select(i => texts[i]).ToArray(), isQuery: false, cancellationToken).ConfigureAwait(false);
            for (var k = 0; k < batch.Length; k++) index.Entries[documents[batch[k]].RelativePath] = new IndexEntry(hashes[batch[k]], vectors[k]);
        }
        foreach (var gone in index.Entries.Keys.Except(documents.Select(d => d.RelativePath)).ToList()) index.Entries.Remove(gone);
        if (stale.Length > 0) SaveIndex(indexPath, index);

        var q = (await embeddings.EmbedAsync([query], isQuery: true, cancellationToken).ConfigureAwait(false))[0];
        return documents.Select(d => Math.Max(0, Cosine(q, index.Entries[d.RelativePath].Vector))).ToArray();
    }

    private async Task<bool> SafeAvailableAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await embeddings!.IsAvailableAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException)
        {
            return false;
        }
    }

    private sealed record IndexEntry(string Hash, float[] Vector);
    private sealed record EmbeddingIndex(string Model, Dictionary<string, IndexEntry> Entries);

    private static EmbeddingIndex LoadIndex(string path, string model)
    {
        try
        {
            if (File.Exists(path) && JsonSerializer.Deserialize<EmbeddingIndex>(File.ReadAllText(path), IndexJson) is { } index && index.Model == model)
                return index with { Entries = new Dictionary<string, IndexEntry>(index.Entries, StringComparer.Ordinal) };
        }
        catch (Exception ex) when (ex is IOException or JsonException or NotSupportedException or InvalidOperationException)
        {
            // Rebuilt below.
        }
        return new EmbeddingIndex(model, new Dictionary<string, IndexEntry>(StringComparer.Ordinal));
    }

    private static void SaveIndex(string path, EmbeddingIndex index)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(index, IndexJson));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or InvalidOperationException)
        {
            // The index is only a cache.
        }
    }

    private static double Cosine(float[] a, float[] b)
    {
        double dot = 0, na = 0, nb = 0;
        for (var i = 0; i < Math.Min(a.Length, b.Length); i++)
        {
            dot += a[i] * b[i];
            na += a[i] * a[i];
            nb += b[i] * b[i];
        }
        return na == 0 || nb == 0 ? 0 : dot / Math.Sqrt(na * nb);
    }

    private static string Snippet(FindingDocument d, string[] terms)
    {
        var lines = d.Text.Split('\n').Select(l => l.Trim().TrimStart('>', ' ')).Where(l => l.Length > 0 && !l.StartsWith('#') && !l.StartsWith('|')).ToList();
        var hit = lines.FirstOrDefault(l => terms.Any(t => l.Contains(t, StringComparison.OrdinalIgnoreCase))) ?? lines.Skip(2).FirstOrDefault() ?? string.Empty;
        return Truncate(hit.Replace("**", string.Empty, StringComparison.Ordinal), 220);
    }

    // ---- Helpers ------------------------------------------------------------------------------------------------

    private string RequireVault() => TryVault(out var vault)
        ? vault
        : throw new InvalidOperationException("No Second Brain vault is configured or the folder does not exist (Settings → Second Brain).");

    private bool TryVault(out string vault)
    {
        vault = settings().VaultPath?.Trim() ?? string.Empty;
        if (vault.Length == 0 || !Directory.Exists(vault)) return false;
        vault = Path.GetFullPath(vault).TrimEnd('\\', '/');
        return true;
    }

    private static KnowledgeStatistics CountNotes(string vault)
    {
        int Count(string folder) => Directory.Exists(Path.Combine(vault, folder)) ? Directory.EnumerateFiles(Path.Combine(vault, folder), "*.md").Count() : 0;
        var validated = Notes(vault, FindingsFolder).Count(n => ParseStatus(n.Note.Get("status")) is not (null or ValidationStatus.New or ValidationStatus.NeedsReview));
        return new KnowledgeStatistics(Count(ProjectsFolder), Count(ScansFolder), Count(FindingsFolder), validated);
    }

    private static IEnumerable<(string Link, MarkdownNote Note)> Notes(string vault, string folder)
    {
        var dir = Path.Combine(vault, folder);
        if (!Directory.Exists(dir)) yield break;
        foreach (var file in Directory.EnumerateFiles(dir, "*.md"))
        {
            MarkdownNote note;
            try
            {
                note = MarkdownNote.Parse(File.ReadAllText(file));
            }
            catch (IOException)
            {
                continue;
            }
            yield return ($"{folder}/{Path.GetFileNameWithoutExtension(file)}", note);
        }
    }

    private static string? FindFindingNote(string vault, string fingerprint)
    {
        var dir = Path.Combine(vault, FindingsFolder);
        if (!Directory.Exists(dir)) return null;
        foreach (var file in Directory.EnumerateFiles(dir, $"*({Short(fingerprint)}).md"))
        {
            if (MarkdownNote.Parse(File.ReadAllText(file)).Get("fingerprint") == fingerprint) return file;
        }
        return null;
    }

    /// <summary>Name of the project note for a scanned folder, or null without a vault.</summary>
    public string? ProjectNameFor(string rootFolder) => TryVault(out var vault) ? ProjectName(vault, rootFolder) : null;

    /// <summary>Folder name, made unique with a short hash when another folder of the same name was recorded.</summary>
    private static string ProjectName(string vault, string root)
    {
        var full = Path.GetFullPath(root).TrimEnd('\\', '/');
        var name = SafeName(Path.GetFileName(full) is { Length: > 0 } n ? n : full, 60);
        var path = Path.Combine(vault, ProjectsFolder, name + ".md");
        if (!File.Exists(path)) return name;
        var existing = MarkdownNote.Parse(File.ReadAllText(path)).Get("root");
        return existing is null || string.Equals(Path.GetFullPath(existing).TrimEnd('\\', '/'), full, StringComparison.OrdinalIgnoreCase)
            ? name
            : $"{name} ({Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(full.ToUpperInvariant())))[..6]})";
    }

    private static void WriteNote(string path, MarkdownNote note)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        // Written in place, not via temp file + rename: Obsidian's file watcher drops many rename events when a scan
        // writes dozens of notes at once, and those notes then stay invisible ("not found") until Obsidian restarts.
        var bytes = new UTF8Encoding(false).GetBytes(note.Render());
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                File.WriteAllBytes(path, bytes);
                return;
            }
            catch (IOException) when (attempt < 4)
            {
                // Obsidian or a sync client may hold the file for a moment.
                Thread.Sleep(100 * (attempt + 1));
            }
        }
    }

    public static ValidationStatus? ParseStatus(string? value)
    {
        var compact = new string((value ?? string.Empty).Where(char.IsLetter).ToArray());
        return Enum.TryParse<ValidationStatus>(compact, ignoreCase: true, out var status) ? status : null;
    }

    private DateTimeOffset Local(DateTimeOffset value) => TimeZoneInfo.ConvertTime(value, _time.LocalTimeZone);

    /// <summary>8 hex characters identifying a finding in its file name; non-standard fingerprints are hashed first.</summary>
    private static string Short(string fingerprint) =>
        fingerprint.StartsWith("wgf1:", StringComparison.Ordinal) && fingerprint.Length >= 13 && fingerprint[5..13].All(Uri.IsHexDigit)
            ? fingerprint[5..13]
            : Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprint)))[..8];

    private static string Redact(string? text) => SourceRedactor.Redact(text);

    private static bool IsPlaceholder(string? block) => string.IsNullOrWhiteSpace(block) || block.TrimStart().StartsWith('_');

    public static string SafeName(string value, int max)
    {
        var cleaned = InvalidNameChars().Replace(value, " ");
        cleaned = Spaces().Replace(cleaned, " ").Trim().TrimEnd('.');
        if (cleaned.Length > max) cleaned = cleaned[..max].TrimEnd();
        return cleaned.Length == 0 ? "untitled" : cleaned;
    }

    private static string Tag(string value) => Spaces().Replace(InvalidNameChars().Replace(value.ToLowerInvariant(), "-"), "-");

    private static string EscapeLink(string text) => text.Replace("|", "/", StringComparison.Ordinal).Replace("]", ")", StringComparison.Ordinal).Replace("[", "(", StringComparison.Ordinal);

    private static string Cell(string? text) => (text ?? string.Empty).Replace("|", "\\|", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);

    private static string Truncate(string text, int max) => text.Length <= max ? text : text[..max] + "…";

    private static string[] Tokens(string query) =>
        Spaces().Split(query.ToLowerInvariant()).Select(t => t.Trim('.', ',', '"', '\'', '(', ')')).Where(t => t.Length >= 2).Distinct().ToArray();

    private static int Count(string text, string term)
    {
        int count = 0, index = 0;
        while ((index = text.IndexOf(term, index, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            count++;
            index += term.Length;
        }
        return count;
    }

    [GeneratedRegex(@"[\\/:*?""<>|#^\[\]]")]
    private static partial Regex InvalidNameChars();

    [GeneratedRegex(@"\s+")]
    private static partial Regex Spaces();

    // [[target]], [[target|alias]] and the table-escaped [[target\|alias]].
    [GeneratedRegex(@"\[\[(?<target>[^\]|\\]+)(?:\\?\|[^\]]*)?\]\]")]
    private static partial Regex WikiLink();

    [GeneratedRegex(@"<!--[\s\S]*?-->")]
    private static partial Regex HtmlComment();

    [GeneratedRegex(@"<!-- scan:(?<scan>[0-9a-f]{32}) seen:(?<seen>\S+) location:(?<location>.*?) -->")]
    private static partial Regex OccurrenceLine();
}
