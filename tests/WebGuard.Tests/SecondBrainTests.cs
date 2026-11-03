using System.Text.Json.Nodes;
using WebGuard.Core.AI;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Knowledge;
using WebGuard.Core.Scanning;
using WebGuard.Mcp;
using WebGuard.Persistence;
using WebGuard.Presentation.Services;
using WebGuard.Presentation.ViewModels;

namespace WebGuard.Tests;

public static class SecondBrainTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 4, 8, 30, 0, TimeSpan.Zero);
    // Fake key assembled at runtime so no secret-shaped literal sits in the source (GitHub push protection flags those).
    private static readonly string Secret = string.Concat("sk_", "live_", "0123456789abcdef01234567");

    [Test]
    public static async Task Scan_with_findings_creates_linked_redacted_notes()
    {
        using var vault = new TempFolder();
        using var brain = Brain(vault.Path);
        var eval = Finding("semgrep", "webguard.js.eval-dynamic", "src/app.js", 5, "Dynamic code evaluation with eval()", Severity.High);
        var secret = Finding("gitleaks", "stripe-access-token", "src/app.js", 3, "Hardcoded secret: stripe-access-token", Severity.High) with
        {
            Description = "Found key " + Secret,
            Evidence = [new Evidence("secret", "Redacted match", "PAYMENT_KEY = \"" + Secret + "\"", "gitleaks")],
        };
        await brain.SaveScanAsync(Report(@"C:\work\shop", Now, [eval, secret], enginesRan: true), CancellationToken.None);

        var files = Directory.EnumerateFiles(vault.Path, "*.md", SearchOption.AllDirectories).Select(f => Path.GetRelativePath(vault.Path, f).Replace('\\', '/')).ToArray();
        Assert.True(files.Contains("Dashboard.md") && files.Contains("Projects/shop.md"), "dashboard and project notes");
        Assert.Equal(1, files.Count(f => f.StartsWith("Scans/", StringComparison.Ordinal)), "one scan note");
        Assert.Equal(2, files.Count(f => f.StartsWith("Findings/", StringComparison.Ordinal)), "one note per finding");
        Assert.Equal(2, files.Count(f => f.StartsWith("Rules/", StringComparison.Ordinal)), "one note per rule");
        Assert.True(Directory.EnumerateFiles(vault.Path, "*", SearchOption.AllDirectories).All(f => !File.ReadAllText(f).Contains(Secret, StringComparison.Ordinal)),
            "secret never written to the vault");

        var note = File.ReadAllText(FindingFile(vault.Path, eval));
        Assert.True(note.Contains($"fingerprint: \"{eval.Fingerprint}\"", StringComparison.Ordinal), "fingerprint property");
        Assert.True(note.Contains("status: New", StringComparison.Ordinal) && note.Contains("present: true", StringComparison.Ordinal), "status and presence");
        Assert.True(note.Contains("[[Scans/", StringComparison.Ordinal) && note.Contains("projects: [\"[[Projects/shop]]\"]", StringComparison.Ordinal), "links to scan and project");
        Assert.True(note.Contains("## My notes", StringComparison.Ordinal), "personal section");
        var scan = File.ReadAllText(Directory.EnumerateFiles(Path.Combine(vault.Path, "Scans")).Single());
        Assert.True(scan.Contains("result: findings", StringComparison.Ordinal) && scan.Contains("[!danger] 2 finding(s)", StringComparison.Ordinal), "scan result");
    }

    [Test]
    public static async Task Clean_scans_are_recorded_and_disappearing_findings_are_marked()
    {
        using var vault = new TempFolder();
        using var brain = Brain(vault.Path);
        var eval = Finding("semgrep", "r.eval", "src/app.js", 5, "Dynamic code evaluation with eval()", Severity.High);
        await brain.SaveScanAsync(Report(@"C:\work\shop", Now, [eval], enginesRan: true), CancellationToken.None);

        // A person writes into the note and adds a property; neither may be lost on the next scans.
        var path = FindingFile(vault.Path, eval);
        File.WriteAllText(path, File.ReadAllText(path).Replace("---\n# ", "owner: \"team-a\"\n---\n# ", StringComparison.Ordinal) + "Ticket SEC-42: fix in sprint 7.\n");

        await brain.SaveScanAsync(Report(@"C:\work\shop", Now.AddHours(1), [], enginesRan: true), CancellationToken.None);
        var note = File.ReadAllText(path);
        Assert.True(note.Contains("present: false", StringComparison.Ordinal) && note.Contains("Not seen in [[Scans/", StringComparison.Ordinal), "marked as not seen");
        Assert.True(note.Contains("owner: \"team-a\"", StringComparison.Ordinal) && note.Contains("Ticket SEC-42", StringComparison.Ordinal), "personal property and text kept");
        var clean = Directory.EnumerateFiles(Path.Combine(vault.Path, "Scans")).Select(File.ReadAllText).Single(t => t.Contains("result: clean", StringComparison.Ordinal));
        Assert.True(clean.Contains("[!success] Clean", StringComparison.Ordinal), "clean scan recorded");
        Assert.True(File.ReadAllText(Path.Combine(vault.Path, "Projects", "shop.md")).Contains("last_result: clean", StringComparison.Ordinal), "project shows clean");

        await brain.SaveScanAsync(Report(@"C:\work\shop", Now.AddHours(2), [eval], enginesRan: true), CancellationToken.None);
        note = File.ReadAllText(path);
        Assert.True(note.Contains("present: true", StringComparison.Ordinal) && note.Contains("occurrences: 2", StringComparison.Ordinal), "regression seen again");

        await brain.SaveScanAsync(Report(@"C:\work\shop", Now.AddHours(3), [], enginesRan: false), CancellationToken.None);
        Assert.True(File.ReadAllText(path).Contains("present: true", StringComparison.Ordinal), "a scan without engines proves nothing");
        Assert.True(Directory.EnumerateFiles(Path.Combine(vault.Path, "Scans")).Select(File.ReadAllText).Any(t => t.Contains("result: not-analyzed", StringComparison.Ordinal)),
            "inventory-only scan is not called clean");
    }

    [Test]
    public static async Task Verdicts_and_ai_analyses_are_kept_and_read_back()
    {
        using var vault = new TempFolder();
        using var brain = Brain(vault.Path);
        var eval = Finding("semgrep", "r.eval", "src/app.js", 5, "Dynamic code evaluation with eval()", Severity.High);
        await brain.SaveScanAsync(Report(@"C:\work\shop", Now, [eval], enginesRan: true), CancellationToken.None);

        await brain.RecordValidationAsync(new ValidationRecord(eval.Fingerprint, ValidationStatus.FalsePositive, "dell", "input is a constant", Now), CancellationToken.None);
        var statuses = await brain.GetValidationStatusesAsync([eval.Fingerprint, "wgf1:unknown"], CancellationToken.None);
        Assert.Equal(ValidationStatus.FalsePositive, statuses[eval.Fingerprint], "verdict read back");
        Assert.True(!statuses.ContainsKey("wgf1:unknown"), "unknown finding has no verdict");

        // Editing the property in Obsidian, in a human spelling, is honoured too.
        var path = FindingFile(vault.Path, eval);
        File.WriteAllText(path, File.ReadAllText(path).Replace("status: FalsePositive", "status: Accepted risk", StringComparison.Ordinal));
        Assert.Equal(ValidationStatus.AcceptedRisk, (await brain.GetValidationStatusesAsync([eval.Fingerprint], CancellationToken.None))[eval.Fingerprint], "edited in Obsidian");

        await brain.SaveScanAsync(Report(@"C:\work\shop", Now.AddHours(1), [eval with { Status = ValidationStatus.New }], enginesRan: true), CancellationToken.None);
        Assert.True(File.ReadAllText(path).Contains("status: Accepted risk", StringComparison.Ordinal), "a rescan never overwrites the verdict");

        await brain.SaveAnalysisAsync(eval, new AiAnalysis(eval.Id, "qwen/qwen3.5-9b", "RCE via expr", "attacker runs code", "use mathjs", Confidence.High, false, Now), CancellationToken.None);
        var text = File.ReadAllText(path);
        Assert.True(text.Contains("[!warning] AI hypothesis — not verified", StringComparison.Ordinal) && text.Contains("use mathjs", StringComparison.Ordinal), "analysis stored as hypothesis");
        Assert.True(!text.Contains("No AI analysis yet", StringComparison.Ordinal) && text.Contains("ai_analyses: 1", StringComparison.Ordinal), "placeholder replaced, counted");
        Assert.True(text.Contains("**AcceptedRisk**", StringComparison.Ordinal) || text.Contains("**FalsePositive** by dell — input is a constant", StringComparison.Ordinal), "validation history");
    }

    [Test]
    public static async Task Search_blends_keywords_with_semantic_similarity()
    {
        using var vault = new TempFolder();
        var eval = Finding("semgrep", "r.eval", "src/app.js", 5, "Dynamic code evaluation with eval()", Severity.High);
        var sql = Finding("semgrep", "r.sql", "src/Repo.cs", 9, "SQL command built by string concatenation", Severity.High);
        using (var keywordOnly = Brain(vault.Path))
        {
            await keywordOnly.SaveScanAsync(Report(@"C:\work\shop", Now, [eval, sql], enginesRan: true), CancellationToken.None);
            var hits = await keywordOnly.SearchSimilarAsync("sql concatenation", 5, CancellationToken.None);
            Assert.Equal("SQL command built by string concatenation", hits[0].Title, "keyword hit first");
            Assert.True(hits.All(h => h.Title != eval.Title), "unrelated finding not returned");
            Assert.True(hits[0].NotePath.StartsWith("Findings/", StringComparison.Ordinal) && hits[0].Project == "shop", "note path and project");
        }

        var embeddings = new FakeEmbeddings();
        using var semantic = new ObsidianSecondBrain(() => new SecondBrainSettings(vault.Path), embeddings, new FixedTimeProvider(Now));
        var meaning = await semantic.SearchSimilarAsync("attacker executes arbitrary code", 5, CancellationToken.None);
        Assert.Equal(eval.Title, meaning[0].Title, "semantic match without shared keywords");
        Assert.True(File.Exists(Path.Combine(vault.Path, ".webguard", "embeddings.json")), "embedding index cached");
        var calls = embeddings.DocumentCalls;
        await semantic.SearchSimilarAsync("attacker executes arbitrary code", 5, CancellationToken.None);
        Assert.Equal(calls, embeddings.DocumentCalls, "unchanged notes are not embedded again");
    }

    [Test]
    public static async Task Workspace_records_scans_and_applies_recorded_verdicts()
    {
        using var temp = new TempFolder();
        temp.Write("project/a.js", "x");
        var vaultPath = Path.Combine(temp.Path, "vault");
        Directory.CreateDirectory(vaultPath);
        using var brain = Brain(vaultPath);
        var finding = Finding("fixed", "f.rule", "a.js", 1, "Issue", Severity.High);
        await brain.SaveScanAsync(Report(Path.Combine(temp.Path, "project"), Now, [finding], enginesRan: true), CancellationToken.None);
        await brain.RecordValidationAsync(new ValidationRecord(finding.Fingerprint, ValidationStatus.FalsePositive, "dell", null, Now), CancellationToken.None);

        var store = new MemorySettingsStore();
        var settings = new SettingsService(store);
        settings.Update(s => s with { SecondBrainVaultPath = vaultPath });
        var workspace = new ScanWorkspaceViewModel(new WebGuard.Scanner.LocalFolderScanner([new FixedEngine([finding])]), new WebGuard.Scanner.JsonReportExporter(),
            new WebGuard.Scanner.InMemoryScanHistoryStore(), settings, new FakeFolderPicker(Path.Combine(temp.Path, "project")), new FakeSaveDialog(null),
            new FakeClipboard(), new FakeDialogs(), brain);
        workspace.BrowseCommand.Execute(null);
        await workspace.StartScanAsync();

        Assert.Equal(ValidationStatus.FalsePositive, workspace.Report!.Findings.Single().Status, "verdict applied to the new scan");
        Assert.True(workspace.StatusMessage.Contains("Recorded in the Second Brain", StringComparison.Ordinal), "status line says it was recorded");
        Assert.Equal(2, Directory.EnumerateFiles(Path.Combine(vaultPath, "Scans")).Count(), "second scan recorded");

        var findings = new FindingsViewModel(new EngineCatalogViewModel([]), null, brain, settings);
        findings.Load(workspace.Report!);
        await findings.SetStatusAsync(findings.SelectedFinding!.Finding, ValidationStatus.Fixed);
        Assert.Equal(ValidationStatus.Fixed, findings.SelectedFinding!.Finding.Status, "verdict shown in the list");
        Assert.Equal(ValidationStatus.Fixed, (await brain.GetValidationStatusesAsync([finding.Fingerprint], CancellationToken.None))[finding.Fingerprint], "verdict stored");
    }

    [Test]
    public static async Task Mcp_second_brain_tools_search_and_save_hypotheses()
    {
        using var temp = new TempFolder();
        temp.Write("project/src/db.cs", "var q = \"SELECT * FROM t WHERE id=\" + id;");
        var vaultPath = Path.Combine(temp.Path, "vault");
        Directory.CreateDirectory(vaultPath);
        using var brain = Brain(vaultPath);
        var services = new McpServices(() => new AppSettings(), () => [], [], new WebGuard.Intelligence.PlannedVulnerabilityIntelligence(), [],
            new WebGuard.AI.PlannedAiSecurityAnalyst(), brain);
        var toolset = new McpToolset(new ProjectScope(Path.Combine(temp.Path, "project")), services,
            new McpAuditLog(Path.Combine(temp.Path, "audit.jsonl")), ["save_security_finding"]);

        var (saved, savedError) = await toolset.CallAsync("save_security_finding", new JsonObject
        {
            ["path"] = "src/db.cs", ["line"] = 1, ["title"] = "SQL injection via string concatenation",
            ["description"] = "id is concatenated into the query.", ["severity"] = "High", ["cwe"] = "CWE-89",
        }, CancellationToken.None);
        Assert.True(!savedError && saved.Contains("NeedsReview", StringComparison.Ordinal), "saved as a hypothesis to review");
        var note = File.ReadAllText(Directory.EnumerateFiles(Path.Combine(vaultPath, "Findings")).Single());
        Assert.True(note.Contains("status: NeedsReview", StringComparison.Ordinal) && note.Contains("origin: AiHypothesis", StringComparison.Ordinal), "marked as unverified");

        var (found, foundError) = await toolset.CallAsync("search_similar_findings", new JsonObject { ["query"] = "sql injection" }, CancellationToken.None);
        Assert.True(!foundError && found.Contains("SQL injection via string concatenation", StringComparison.Ordinal), "found through search");

        var (escape, escapeError) = await toolset.CallAsync("save_security_finding", new JsonObject
        {
            ["path"] = "../outside.cs", ["title"] = "x", ["description"] = "x", ["severity"] = "Low",
        }, CancellationToken.None);
        Assert.True(escapeError && escape.Contains("outside", StringComparison.Ordinal), "path scope enforced");
    }

    // ---- Helpers ---------------------------------------------------------------------------------------------------

    private static ObsidianSecondBrain Brain(string vault) => new(() => new SecondBrainSettings(vault), null, new FixedTimeProvider(Now));

    private static string FindingFile(string vault, SecurityFinding finding) =>
        Directory.EnumerateFiles(Path.Combine(vault, "Findings"), $"*({finding.Fingerprint[5..13]}).md").Single();

    private static SecurityFinding Finding(string engine, string rule, string path, int line, string title, Severity severity) => new(
        Guid.NewGuid(), FindingFingerprint.Compute(engine, rule, path, title), engine, rule, title, title + " — description.", FindingCategory.Vulnerability,
        severity, Confidence.Medium, FindingOrigin.Engine, new SourceLocation(path, line, line), [], ["CWE-95"], [], "Fix it.", ValidationStatus.New, Now);

    private static ScanReport Report(string root, DateTimeOffset started, IReadOnlyList<SecurityFinding> findings, bool enginesRan) => new(
        ScanReport.CurrentSchemaVersion, "0.5.0", Guid.NewGuid(), root, "pc", started, started.AddSeconds(12), ScanOptions.Default,
        new ScanStatistics(3, 3, 0, 0, 1234, 1),
        [new EngineRunSummary("semgrep", "Semgrep CE", enginesRan ? "Completed" : "NotInstalled", "1.0", findings.Count, "msg")], [], findings);

    private sealed class FixedEngine(IReadOnlyList<SecurityFinding> findings) : ISecurityEngine
    {
        public SecurityEngineInfo Info { get; } = new("fixed", "Fixed", EngineKind.StaticAnalysis, "test", "Phase 2", null);
        public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new EngineStatus(EngineAvailability.Ready, "1", null, "ok"));
        public Task<EngineScanResult> ScanAsync(EngineScanRequest request, IProgress<EngineProgress>? progress, CancellationToken cancellationToken) =>
            Task.FromResult(new EngineScanResult("fixed", true, findings, TimeSpan.Zero, null, null));
    }

    /// <summary>Two-dimensional "meaning" vectors: code execution vs. data access, enough to test the blending.</summary>
    private sealed class FakeEmbeddings : ITextEmbeddingService
    {
        public int DocumentCalls { get; private set; }
        public string ModelId => "fake-embed";
        public Task<bool> IsAvailableAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<IReadOnlyList<float[]>> EmbedAsync(IReadOnlyList<string> texts, bool isQuery, CancellationToken cancellationToken)
        {
            if (!isQuery) DocumentCalls++;
            return Task.FromResult<IReadOnlyList<float[]>>(texts.Select(t =>
            {
                var code = t.Contains("eval", StringComparison.OrdinalIgnoreCase) || t.Contains("execut", StringComparison.OrdinalIgnoreCase) ? 1f : 0.05f;
                var data = t.Contains("sql", StringComparison.OrdinalIgnoreCase) ? 1f : 0.05f;
                return new[] { code, data };
            }).ToArray());
        }
    }
}
