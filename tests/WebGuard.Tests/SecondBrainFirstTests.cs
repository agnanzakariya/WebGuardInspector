using WebGuard.AI;
using WebGuard.Core.AI;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Fixing;
using WebGuard.Core.Knowledge;
using WebGuard.Core.Scanning;
using WebGuard.Persistence;
using WebGuard.Presentation.Services;
using WebGuard.Presentation.ViewModels;
using WebGuard.Scanner;

namespace WebGuard.Tests;

/// <summary>Second Brain first: skip unchanged files, recognise confirmed files, reuse verdicts, fixes and analyses.</summary>
public static class SecondBrainFirstTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 4, 9, 0, 0, TimeSpan.Zero);

    [Test]
    public static async Task Rescans_only_send_changed_files_to_incremental_engines()
    {
        using var project = new TempFolder();
        using var cacheDir = new TempFolder();
        for (var i = 1; i <= 4; i++) project.Write($"src/f{i}.php", i == 2 ? "<?php BAD();" : "<?php ok();");
        var folderEngine = new MarkerEngine("folder-engine", IncrementalScanMode.ChangedFilesFolder);
        var listEngine = new MarkerEngine("list-engine", IncrementalScanMode.ChangedFilesList);
        var fullEngine = new MarkerEngine("full-engine", IncrementalScanMode.None);
        var scanner = new LocalFolderScanner([folderEngine, listEngine, fullEngine], resultCache: new FileScanResultCacheStore(cacheDir.Path));

        var first = await scanner.ScanAsync(project.Path, ScanOptions.Default, null, CancellationToken.None);
        Assert.Equal(3, first.Findings.Count, "one finding per engine");
        Assert.Equal(4, folderEngine.LastSeen.Count, "first scan: every file");

        var second = await scanner.ScanAsync(project.Path, ScanOptions.Default, null, CancellationToken.None);
        Assert.Equal(1, folderEngine.Runs, "nothing changed: folder engine not run again");
        Assert.Equal(1, listEngine.Runs, "nothing changed: list engine not run again");
        Assert.Equal(2, fullEngine.Runs, "non-incremental engine always runs");
        Assert.Equal(3, second.Findings.Count, "findings reused");
        Assert.True(second.Engines.Single(e => e.EngineId == "folder-engine").Message!.Contains("No file changed", StringComparison.Ordinal), "summary says so");
        Assert.True(second.Findings.All(f => first.Findings.All(o => o.Id != f.Id)), "reused findings get new ids");

        project.Write("src/f3.php", "<?php BAD(); // new");
        var third = await scanner.ScanAsync(project.Path, ScanOptions.Default, null, CancellationToken.None);
        Assert.True(folderEngine.LastSeen.SequenceEqual(["src/f3.php"]), "folder engine sees only the changed file: " + string.Join(",", folderEngine.LastSeen));
        Assert.True(folderEngine.LastRoot != project.Path, "folder engine scanned a copy");
        Assert.True(listEngine.LastSeen.SequenceEqual(["src/f3.php"]) && listEngine.LastRoot == project.Path, "list engine gets the changed file in the real folder");
        Assert.Equal(6, third.Findings.Count, "old finding reused plus new finding, per engine");
        Assert.True(third.Findings.All(f => f.Location.RelativePath is "src/f2.php" or "src/f3.php"), "paths are the project's");

        folderEngine.Stamp = "rules-v2";
        await scanner.ScanAsync(project.Path, ScanOptions.Default, null, CancellationToken.None);
        Assert.Equal(4, folderEngine.LastSeen.Count, "new rules: everything again");

        await scanner.ScanAsync(project.Path, ScanOptions.Default with { ReuseUnchangedResults = false }, null, CancellationToken.None);
        Assert.Equal(4, listEngine.LastSeen.Count, "reuse turned off: everything");
    }

    [Test]
    public static async Task Confirmed_files_are_recognised_anywhere_and_verdicts_follow_identical_files()
    {
        using var vault = new TempFolder();
        using var brain = new ObsidianSecondBrain(() => new SecondBrainSettings(vault.Path), null, new FixedTimeProvider(Now));
        const string sha = "aa11bb22cc33dd44ee55ff6600778899aa11bb22cc33dd44ee55ff6600778899";
        var shell = Finding("yara-x", "php_webshell", "wp-content/plugins/x/shell.php", 3, FindingCategory.Malware);
        await brain.SaveScanAsync(Report(@"C:\sites\shop", [File("wp-content/plugins/x/shell.php", sha)], [shell]), CancellationToken.None);
        await brain.RecordValidationAsync(new ValidationRecord(shell.Fingerprint, ValidationStatus.Confirmed, "me", null, Now), CancellationToken.None);

        var engine = new SecondBrainMemoryEngine(brain, () => true, new FixedTimeProvider(Now));
        Assert.Equal(EngineAvailability.Ready, (await engine.GetStatusAsync(CancellationToken.None)).Availability, "ready with a vault");
        var other = await engine.ScanAsync(new EngineScanRequest(Guid.NewGuid(), @"C:\sites\blog", [File("plugins/copy.php", sha), File("index.php", new string('0', 64))],
            Path.GetTempPath(), TimeSpan.FromMinutes(1)), null, CancellationToken.None);
        var hit = other.Findings.Single();
        Assert.True(hit is { Category: FindingCategory.Malware, Status: ValidationStatus.Confirmed, Severity: Severity.High } &&
                    hit.Location.RelativePath == "plugins/copy.php" && hit.Description.Contains("shell.php", StringComparison.Ordinal),
            "identical copy in another project flagged as confirmed");
        var same = await engine.ScanAsync(new EngineScanRequest(Guid.NewGuid(), @"C:\sites\shop", [File("wp-content/plugins/x/shell.php", sha)],
            Path.GetTempPath(), TimeSpan.FromMinutes(1)), null, CancellationToken.None);
        Assert.Equal(0, same.Findings.Count, "same file in the same project is left to the engine that found it");
        var off = new SecondBrainMemoryEngine(brain, () => false);
        Assert.Equal(EngineAvailability.Disabled, (await off.GetStatusAsync(CancellationToken.None)).Availability, "can be turned off");

        var known = await brain.GetKnownFindingsAsync([sha.ToUpperInvariant()], CancellationToken.None);
        Assert.True(known.Single() is { IsVerified: true, Status: ValidationStatus.Confirmed, RuleId: "php_webshell", StartLine: 3 }, "known findings by hash");
    }

    [Test]
    public static async Task Scan_applies_verdicts_of_identical_files_from_other_projects()
    {
        using var vault = new TempFolder();
        using var projectA = new TempFolder();
        using var projectB = new TempFolder();
        const string code = "<?php\n$x = md5($y);\n";
        projectA.Write("lib/cache.php", code);
        projectB.Write("vendor/lib/cache.php", code);
        var store = new MemorySettingsStore();
        var settings = new SettingsService(store);
        settings.Update(s => s with { SecondBrainVaultPath = vault.Path, SetupCompleted = true });
        using var brain = new ObsidianSecondBrain(() => new SecondBrainSettings(vault.Path), null, new FixedTimeProvider(Now));
        var engine = new PathEngine("semgrep", "weak-hash", 2);

        var first = await RunScanAsync(engine, settings, brain, projectA.Path);
        await brain.RecordValidationAsync(new ValidationRecord(first.Findings.Single().Fingerprint, ValidationStatus.FalsePositive, "me", null, Now),
            CancellationToken.None);

        var second = await RunScanAsync(engine, settings, brain, projectB.Path);
        Assert.Equal(ValidationStatus.FalsePositive, second.Findings.Single().Status, "verdict of the identical file in project A applied");

        settings.Update(s => s with { SecondBrainFirst = false });
        using var projectC = new TempFolder();
        projectC.Write("cache.php", code);
        var third = await RunScanAsync(engine, settings, brain, projectC.Path);
        Assert.Equal(ValidationStatus.New, third.Findings.Single().Status, "off: only exact fingerprints");
    }

    [Test]
    public static async Task Applied_fixes_are_reused_for_the_same_rule_without_asking_the_ai()
    {
        using var vault = new TempFolder();
        using var projectA = new TempFolder();
        using var projectB = new TempFolder();
        using var backups = new TempFolder();
        projectA.Write("app.php", "<?php\nrun_remote($_REQUEST['c']);\necho 'a';\n");
        var fileB = projectB.Write("admin/tools.php", "<?php\n// another file\n$z = 1;\nrun_remote($_REQUEST['c']);\necho 'b';\n");
        var settings = new SettingsService(new MemorySettingsStore());
        settings.Update(s => s with { SecondBrainVaultPath = vault.Path, SetupCompleted = true });
        using var brain = new ObsidianSecondBrain(() => new SecondBrainSettings(vault.Path), null, new FixedTimeProvider(Now));
        var fixer = new CountingFixer(r => new FixProposal(r.Finding.Id, "claude-test", FixVerdict.Fix, "Remove the remote command runner.",
            [new CodeEdit("run_remote($_REQUEST['c']);\n", "")], Confidence.High, Now));
        var findings = new FindingsViewModel(new EngineCatalogViewModel([]), null, brain, settings);
        var page = new FixingViewModel(findings, fixer, new FixApplier(backups.Path), brain, settings);
        await page.RefreshAsync();

        var a = Finding("semgrep", "php-rce", "app.php", 2, FindingCategory.Vulnerability);
        findings.Load(Report(projectA.Path, [], [a]));
        await page.FixAllAsync();
        Assert.Equal(1, fixer.Calls, "first time the AI is asked");
        page.SelectedItem = page.Items.Single();
        await page.ApplyCommand.ExecuteAsync();
        Assert.Equal(FixState.Applied, page.SelectedItem.State, "applied");
        Assert.Equal(1, (await brain.GetRememberedFixesAsync("semgrep", "php-rce", CancellationToken.None)).Count, "fix remembered");

        var b = Finding("semgrep", "php-rce", "admin/tools.php", 4, FindingCategory.Vulnerability);
        findings.Load(Report(projectB.Path, [], [b]));
        await page.FixAllAsync();
        var item = page.Items.Single();
        Assert.Equal(1, fixer.Calls, "reused: the AI is not asked again");
        Assert.True(item is { FromSecondBrain: true, State: FixState.Proposed, CanApply: true }, "remembered fix proposed: " + item.Message);
        Assert.True(item.Proposal!.Explanation.Contains("app.php", StringComparison.Ordinal), "says where it was applied before");
        Assert.True(System.IO.File.ReadAllText(fileB).Contains("run_remote", StringComparison.Ordinal), "nothing written before Apply");

        page.SelectedItem = item;
        Assert.True(page.AskAiCommand.CanExecute(null), "can ask the AI instead");
        await page.AskAiCommand.ExecuteAsync();
        Assert.True(fixer.Calls == 2 && !item.FromSecondBrain && item.State == FixState.Proposed, "AI asked on request");

        settings.Update(s => s with { SecondBrainFirst = false });
        findings.Load(Report(projectB.Path, [], [b]));
        await page.FixAllAsync();
        Assert.Equal(3, fixer.Calls, "off: always the AI");
    }

    [Test]
    public static async Task Analyses_are_found_again_and_prior_verdicts_reach_the_prompts()
    {
        using var vault = new TempFolder();
        using var brain = new ObsidianSecondBrain(() => new SecondBrainSettings(vault.Path), null, new FixedTimeProvider(Now));
        const string sha = "bb11bb22cc33dd44ee55ff6600778899aa11bb22cc33dd44ee55ff6600778899";
        var original = Finding("semgrep", "php-eval", "a/eval.php", 7, FindingCategory.Vulnerability);
        var analysis = new AiAnalysis(original.Id, "qwen", "Evaluates request input.", "RCE.", "Remove eval.", Confidence.High, false, Now);
        await brain.RememberAnalysisAsync(original, sha, analysis, "shop", CancellationToken.None);

        Assert.Equal("Evaluates request input.", (await brain.FindAnalysisAsync(original with { Id = Guid.NewGuid() }, null, CancellationToken.None))?.Analysis.Summary,
            "same fingerprint");
        var copy = Finding("semgrep", "php-eval", "b/other.php", 7, FindingCategory.Vulnerability);
        Assert.Equal("a/eval.php", (await brain.FindAnalysisAsync(copy, sha.ToUpperInvariant(), CancellationToken.None))?.RelativePath, "identical file, same rule and line");
        Assert.True(await brain.FindAnalysisAsync(copy with { Location = new SourceLocation("b/other.php", 9, 9) }, sha, CancellationToken.None) is null, "other line: none");

        var hits = new[]
        {
            new KnowledgeSearchHit("wgf1:1", "eval() on input", 0.8, ValidationStatus.FalsePositive, true, "n.md", "constant string only", Severity.High, "shop"),
            new KnowledgeSearchHit("wgf1:2", "unverified", 0.9, ValidationStatus.New, false, "m.md", "x", Severity.High, null),
            new KnowledgeSearchHit(original.Fingerprint, "itself", 0.99, ValidationStatus.Confirmed, true, "o.md", "x", Severity.High, null),
        };
        var text = PriorKnowledge.Describe(PriorKnowledge.Select(hits, original.Fingerprint));
        Assert.True(text.Contains("[FalsePositive] eval() on input (project shop): constant string only", StringComparison.Ordinal) &&
                    !text.Contains("unverified", StringComparison.Ordinal) && !text.Contains("itself", StringComparison.Ordinal), "only verified, other findings");

        var fixPrompt = ClaudeCodeFixer.BuildPrompt(new FixRequest(original, "<?php eval($x);\n", [], PriorKnowledge: text));
        var analystPrompt = LocalAiSecurityAnalyst.BuildPrompt(new FindingContext(original, "1 | eval($x);", [], text));
        Assert.True(fixPrompt.Contains("PRIOR VERDICTS FROM THE SECOND BRAIN", StringComparison.Ordinal) &&
                    analystPrompt.Contains("PRIOR VERDICTS FROM THE SECOND BRAIN", StringComparison.Ordinal), "hints in both prompts");
    }

    // ---- Helpers ---------------------------------------------------------------------------------------------------

    private static async Task<ScanReport> RunScanAsync(ISecurityEngine engine, SettingsService settings, ISecondBrainRepository brain, string folder)
    {
        var workspace = new ScanWorkspaceViewModel(new LocalFolderScanner([engine]), new JsonReportExporter(), new InMemoryScanHistoryStore(), settings,
            new FakeFolderPicker(folder), new FakeSaveDialog(null), new FakeClipboard(), new FakeDialogs(), brain);
        ScanReport? report = null;
        workspace.ScanCompleted += (_, r) => report = r;
        workspace.FolderPath = folder;
        await workspace.StartScanAsync();
        return report ?? throw new InvalidOperationException("Scan did not complete: " + workspace.StatusMessage);
    }

    private static FileInventoryItem File(string path, string sha) =>
        new(path, Path.GetExtension(path), 10, Now, sha, FileScanStatus.Hashed, 0, null);

    private static SecurityFinding Finding(string engine, string rule, string path, int line, FindingCategory category) => new(
        Guid.NewGuid(), FindingFingerprint.Compute(engine, rule, path, rule + line), engine, rule, "Issue " + rule, "Description.", category,
        Severity.High, Confidence.Medium, FindingOrigin.Engine, new SourceLocation(path, line, line), [], [], [], null, ValidationStatus.New, Now);

    private static ScanReport Report(string root, IReadOnlyList<FileInventoryItem> files, IReadOnlyList<SecurityFinding> findings) => new(
        ScanReport.CurrentSchemaVersion, "0.12.0", Guid.NewGuid(), root, "pc", Now, Now.AddSeconds(5), ScanOptions.Default,
        new ScanStatistics(files.Count, files.Count, 0, 0, 10, 0),
        [new EngineRunSummary("semgrep", "Semgrep CE", "Completed", "1.0", findings.Count, "ok")], files, findings);

    /// <summary>Reports every file under the root that contains "BAD" and remembers what it saw.</summary>
    private sealed class MarkerEngine(string id, IncrementalScanMode mode) : ISecurityEngine, IIncrementalSecurityEngine
    {
        public string Stamp { get; set; } = "rules-v1";
        public int Runs { get; private set; }
        public List<string> LastSeen { get; } = [];
        public string LastRoot { get; private set; } = string.Empty;
        public SecurityEngineInfo Info { get; } = new(id, id, EngineKind.StaticAnalysis, "test", "Phase 2", null);
        public IncrementalScanMode IncrementalMode => mode;
        public string? ConfigurationStamp(EngineStatus status) => Stamp;

        public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new EngineStatus(EngineAvailability.Ready, "1.0", "x.exe", "ok"));

        public Task<EngineScanResult> ScanAsync(EngineScanRequest request, IProgress<EngineProgress>? progress, CancellationToken cancellationToken)
        {
            Runs++;
            LastRoot = request.RootFolder;
            LastSeen.Clear();
            var paths = mode == IncrementalScanMode.ChangedFilesList
                ? request.Files.Select(f => f.RelativePath)
                : Directory.EnumerateFiles(request.RootFolder, "*.php", SearchOption.AllDirectories).Select(p => Path.GetRelativePath(request.RootFolder, p));
            var findings = new List<SecurityFinding>();
            foreach (var path in paths.Select(p => p.Replace('\\', '/')).Order(StringComparer.Ordinal))
            {
                LastSeen.Add(path);
                if (!System.IO.File.ReadAllText(Path.Combine(request.RootFolder, path)).Contains("BAD", StringComparison.Ordinal)) continue;
                findings.Add(new SecurityFinding(Guid.NewGuid(), FindingFingerprint.Compute(id, "bad", path, "BAD"), id, "bad", "Bad call", "d",
                    FindingCategory.Vulnerability, Severity.Medium, Confidence.Medium, FindingOrigin.Engine, new SourceLocation(path, 1, 1), [], [], [], null,
                    ValidationStatus.New, Now));
            }
            return Task.FromResult(new EngineScanResult(id, true, findings, TimeSpan.Zero, null, null));
        }
    }

    /// <summary>Reports one finding at a fixed line in every .php file of the folder.</summary>
    private sealed class PathEngine(string id, string rule, int line) : ISecurityEngine
    {
        public SecurityEngineInfo Info { get; } = new(id, id, EngineKind.StaticAnalysis, "test", "Phase 2", null);

        public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new EngineStatus(EngineAvailability.Ready, "1.0", null, "ok"));

        public Task<EngineScanResult> ScanAsync(EngineScanRequest request, IProgress<EngineProgress>? progress, CancellationToken cancellationToken) =>
            Task.FromResult(new EngineScanResult(id, true, request.Files.Where(f => f.Extension == ".php").Select(f => new SecurityFinding(Guid.NewGuid(),
                FindingFingerprint.Compute(id, rule, f.RelativePath, "md5($y)"), id, rule, "Weak hash", "d", FindingCategory.Vulnerability, Severity.Low,
                Confidence.Medium, FindingOrigin.Engine, new SourceLocation(f.RelativePath, line, line), [], [], [], null, ValidationStatus.New, Now)).ToArray(),
                TimeSpan.Zero, null, null));
    }

    private sealed class CountingFixer(Func<FixRequest, FixProposal> answer) : ICodeFixer
    {
        public int Calls { get; private set; }
        public string DisplayName => "fake";

        public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new EngineStatus(EngineAvailability.Ready, "1", null, "ok"));

        public Task<FixProposal> ProposeAsync(FixRequest request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(answer(request));
        }
    }
}
