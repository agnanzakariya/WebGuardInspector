using System.Text;
using WebGuard.AI;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Fixing;
using WebGuard.Core.Scanning;
using WebGuard.Presentation.ViewModels;

namespace WebGuard.Tests;

/// <summary>Fixes for findings in files too large to send whole, and for dependencies reported in lockfiles.</summary>
public static class LargeFixTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 4, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public static void Lockfile_findings_become_manifest_changes_plus_a_regenerate_command()
    {
        Assert.True(DependencyFixPlan.TryCreate(Dependency(@"Laravel\core\composer.lock", "Packagist/laravel/framework@11.51.0",
            "Upgrade laravel/framework to 10.48.29 or 11.52.0 or 12.40.1 or later."), out var plan), "composer.lock is understood");
        Assert.Equal("laravel/framework", plan.Package, "package");
        Assert.Equal("11.51.0", plan.InstalledVersion, "installed version");
        Assert.Equal(Path.Combine(@"Laravel\core", "composer.json"), plan.ManifestPath, "manifest next to the lockfile");
        Assert.Equal("composer update laravel/framework --with-all-dependencies", plan.Command, "composer command");

        Assert.True(DependencyFixPlan.TryCreate(Dependency("web/package-lock.json", "npm/@scope/widget@1.2.3",
            "Upgrade @scope/widget to 1.2.9 or 2.0.1 or later."), out var npm), "scoped npm package");
        Assert.Equal("@scope/widget", npm.Package, "scoped name keeps its @");
        Assert.Equal("npm install @scope/widget@1.2.9", npm.Command, "lowest fixed version on the same major line");

        Assert.True(!DependencyFixPlan.TryCreate(Dependency("app/requirements.txt", "PyPI/django@4.0.0", null), out _),
            "a manifest that is its own lockfile is edited directly, not planned");
    }

    [Test]
    public static void Requests_use_the_manifest_or_an_excerpt_instead_of_failing_on_size()
    {
        using var temp = new TempFolder();
        temp.Write(@"core\composer.lock", new string('x', 300_000));
        temp.Write(@"core\composer.json", "{\n  \"require\": { \"laravel/framework\": \"^11.0\" }\n}\n");
        var big = new StringBuilder();
        for (var i = 1; i <= 20_000; i++) big.Append("$line").Append(i).Append(" = ").Append(i).Append(";\n");
        temp.Write("big.php", big.ToString());
        var scope = new ProjectScope(temp.Path);

        var lockFinding = Dependency(@"core\composer.lock", "Packagist/laravel/framework@11.51.0", "Upgrade laravel/framework to 11.52.0 or later.");
        Assert.True(FixRequestBuilder.TryBuild(scope, lockFinding, [lockFinding], out var dep, out var error), "dependency request: " + error);
        Assert.Equal(Path.Combine("core", "composer.json"), dep.EditPath, "edits go to the manifest");
        Assert.True(dep.RedactedFileContent.Contains("laravel/framework", StringComparison.Ordinal) && dep.Dependency is not null, "manifest content sent");

        var line = Finding("big.php", 15_000);
        Assert.True(FixRequestBuilder.TryBuild(scope, line, [line], out var excerpt, out error), "excerpt request: " + error);
        Assert.True(excerpt.Excerpt is { FirstLine: 14_800, LastLine: 15_200, TotalLines: > 20_000 }, "200 lines around the finding");
        Assert.True(excerpt.RedactedFileContent.StartsWith("$line14800 ", StringComparison.Ordinal) && excerpt.RedactedFileContent.Length < FixRequestBuilder.MaxExcerptChars,
            "only the excerpt is sent");

        var noLine = Finding("big.php", 0);
        Assert.True(!FixRequestBuilder.TryBuild(scope, noLine, [noLine], out _, out error) && error.Contains("no line", StringComparison.Ordinal),
            "a large file without a line cannot be excerpted");
    }

    [Test]
    public static void Prompt_explains_excerpts_and_dependencies_and_the_answer_carries_a_safe_command()
    {
        var finding = Dependency(@"core\composer.lock", "Packagist/laravel/framework@11.51.0", "Upgrade laravel/framework to 11.52.0 or later.");
        DependencyFixPlan.TryCreate(finding, out var plan);
        var prompt = ClaudeCodeFixer.BuildPrompt(new FixRequest(finding, "{ }\n", [], plan.ManifestPath, null, plan));
        Assert.True(prompt.Contains("VULNERABLE DEPENDENCY", StringComparison.Ordinal) && prompt.Contains("do not edit it", StringComparison.Ordinal),
            "lockfile must not be edited");
        Assert.True(prompt.Contains("Suggested command to regenerate the lockfile: composer update laravel/framework", StringComparison.Ordinal), "command suggested");
        Assert.True(prompt.Contains("FILE CONTENT of " + plan.ManifestPath, StringComparison.Ordinal), "the manifest is the file shown");

        var excerptPrompt = ClaudeCodeFixer.BuildPrompt(new FixRequest(Finding("big.php", 15_000), "x\n", [], null, new FileExcerpt(14_800, 15_200, 20_000)));
        Assert.True(excerptPrompt.Contains("FILE EXCERPT of big.php: lines 14800-15200 of 20000", StringComparison.Ordinal), "excerpt header");

        var answer = ClaudeCodeFixer.ParseResult(Guid.Empty, null, FakeProcessRunner.Ok(
            """{"is_error":false,"structured_output":{"verdict":"cannot_fix","explanation":"Constraint ^11.0 already allows 11.52.0.","confidence":"high","edits":[],"follow_up_command":"composer update laravel/framework --with-all-dependencies"}}"""), Now);
        Assert.Equal("composer update laravel/framework --with-all-dependencies", answer.FollowUpCommand, "command parsed");
        Assert.Equal(null, ClaudeCodeFixer.SafeCommand("composer update\nrm -rf /"), "multi-line commands are dropped");
    }

    [Test]
    public static async Task Fixing_page_applies_manifest_edits_and_shows_the_command_without_running_it()
    {
        using var temp = new TempFolder();
        var lockfile = temp.Write(@"core\composer.lock", "{\"packages\":[]}");
        var manifest = temp.Write(@"core\composer.json", "{\n  \"require\": { \"laravel/framework\": \"^11.0\" }\n}\n");
        var finding = Dependency(@"core\composer.lock", "Packagist/laravel/framework@11.51.0", "Upgrade laravel/framework to 11.52.0 or later.");
        FixRequest? seen = null;
        var fixer = new Fixer(r =>
        {
            seen = r;
            return new FixProposal(r.Finding.Id, "claude-test", FixVerdict.Fix, "Require the fixed release.",
                [new CodeEdit("\"laravel/framework\": \"^11.0\"", "\"laravel/framework\": \"^11.52\"")], Confidence.High, Now,
                "composer update laravel/framework --with-all-dependencies");
        });
        using var backups = new TempFolder();
        var findings = new FindingsViewModel(new EngineCatalogViewModel([]));
        var clipboard = new FakeClipboard();
        var page = new FixingViewModel(findings, fixer, new FixApplier(backups.Path), null, null, clipboard);
        await page.RefreshAsync();
        findings.Load(new ScanReport(ScanReport.CurrentSchemaVersion, "0", Guid.NewGuid(), temp.Path, "pc", Now, Now, ScanOptions.Default,
            new ScanStatistics(2, 2, 0, 0, 10, 1), [], [], [finding]));

        await page.FixAllAsync();
        var item = page.Items.Single();
        Assert.Equal(Path.Combine("core", "composer.json"), seen!.EditPath, "the manifest was sent");
        Assert.True(item is { State: FixState.Proposed, HasFollowUpCommand: true, EditsOtherFile: true }, "manifest change proposed with a command: " + item.Message);

        page.SelectedItem = item;
        page.CopyFollowUpCommand.Execute(null);
        Assert.Equal("composer update laravel/framework --with-all-dependencies", clipboard.Text, "command copied");
        await page.ApplyCommand.ExecuteAsync();
        Assert.True(File.ReadAllText(manifest).Contains("^11.52", StringComparison.Ordinal), "manifest patched");
        Assert.Equal("{\"packages\":[]}", File.ReadAllText(lockfile), "lockfile untouched");
        Assert.True(item.Message.Contains("regenerate the lockfile", StringComparison.Ordinal), "reminds to run the command");
    }

    // ---- Helpers ---------------------------------------------------------------------------------------------------

    private static SecurityFinding Dependency(string path, string coordinate, string? remediation) => new(
        Guid.NewGuid(), FindingFingerprint.Compute("osv-scanner", "GHSA-x", path, coordinate), "osv-scanner", "GHSA-x", "Vulnerable package", "d",
        FindingCategory.VulnerableDependency, Severity.Critical, Confidence.High, FindingOrigin.Engine, new SourceLocation(path, 0, 0),
        [new Evidence("package", "Affected package", coordinate, "osv-scanner")], [], ["GHSA-x"], remediation, ValidationStatus.New, Now);

    private static SecurityFinding Finding(string path, int line) => new(
        Guid.NewGuid(), FindingFingerprint.Compute("semgrep", "r", path, "t" + line), "semgrep", "r", "Issue", "d", FindingCategory.Vulnerability,
        Severity.High, Confidence.Medium, FindingOrigin.Engine, new SourceLocation(path, line, line), [], [], [], null, ValidationStatus.New, Now);

    private sealed class Fixer(Func<FixRequest, FixProposal> answer) : ICodeFixer
    {
        public string DisplayName => "fake";
        public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) => Task.FromResult(new EngineStatus(EngineAvailability.Ready, "1", null, "ok"));
        public Task<FixProposal> ProposeAsync(FixRequest request, CancellationToken cancellationToken) => Task.FromResult(answer(request));
    }
}
