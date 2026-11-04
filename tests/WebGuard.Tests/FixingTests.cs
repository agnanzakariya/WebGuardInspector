using System.Text;
using WebGuard.AI;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Fixing;
using WebGuard.Core.Scanning;
using WebGuard.Presentation.ViewModels;

namespace WebGuard.Tests;

// Sample "malicious" code uses a made-up run_remote() call: real web-shell patterns make antivirus quarantine this file.
public static class FixingTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 4, 9, 0, 0, TimeSpan.Zero);

    [Test]
    public static void Patcher_applies_a_unique_edit_and_builds_a_diff()
    {
        var text = "<?php\n$id = $_GET['id'];\n$sql = \"SELECT * FROM t WHERE id = $id\";\n$db->query($sql);\n";
        var patch = FixPatcher.Apply(text, [new CodeEdit(
            "$sql = \"SELECT * FROM t WHERE id = $id\";\n$db->query($sql);",
            "$stmt = $db->prepare(\"SELECT * FROM t WHERE id = ?\");\n$stmt->execute([$id]);")]);

        Assert.True(patch.Succeeded, "edit applies: " + string.Join(" ", patch.Errors));
        Assert.True(patch.PatchedText.Contains("$db->prepare", StringComparison.Ordinal), "new code written");
        Assert.True(!patch.PatchedText.Contains("WHERE id = $id", StringComparison.Ordinal), "old code gone");
        Assert.Equal(1, patch.Hunks.Count, "one hunk");
        Assert.Equal(2, patch.AddedLines, "added lines");
        Assert.Equal(2, patch.RemovedLines, "removed lines");
        var kinds = patch.Hunks[0].Lines.Select(l => l.Kind).Where(k => k != DiffKind.Context).ToArray();
        Assert.True(kinds.SequenceEqual([DiffKind.Removed, DiffKind.Removed, DiffKind.Added, DiffKind.Added]), "removed lines come first");
        var unified = FixPatcher.ToUnifiedText("a.php", patch.Hunks);
        Assert.True(unified.Contains("-$db->query($sql);", StringComparison.Ordinal) && unified.Contains("+$stmt->execute([$id]);", StringComparison.Ordinal),
            "unified diff text");
    }

    [Test]
    public static void Patcher_refuses_missing_ambiguous_and_empty_edits_without_partial_changes()
    {
        var text = "a();\nb();\na();\n";
        var missing = FixPatcher.Apply(text, [new CodeEdit("b();", "c();"), new CodeEdit("zzz();", "y();")]);
        Assert.True(!missing.Succeeded && missing.PatchedText == text, "all or nothing when one edit is missing");
        Assert.True(missing.Errors[0].StartsWith("Edit 2", StringComparison.Ordinal), "error names the edit");

        var ambiguous = FixPatcher.Apply(text, [new CodeEdit("a();", "x();")]);
        Assert.True(!ambiguous.Succeeded && ambiguous.Errors[0].Contains("2 places", StringComparison.Ordinal), "ambiguous match refused");
        Assert.True(!FixPatcher.Apply(text, []).Succeeded, "no edits is not a fix");
        Assert.True(!FixPatcher.Apply(text, [new CodeEdit("b();", "b();")]).Succeeded, "a no-op is not a fix");
    }

    [Test]
    public static void Patcher_matches_redacted_values_and_never_writes_the_mask()
    {
        const string secret = "hunter2hunter2";
        var text = $"<?php\n$password = \"{secret}\";\nconnect($password);\n";
        var redacted = SourceRedactor.Redact(text, "db.php");
        Assert.True(!redacted.Contains(secret, StringComparison.Ordinal), "the model never sees the secret");

        // Moving the secret to the environment removes it from the file.
        var moved = FixPatcher.Apply(text, [new CodeEdit("$password = \"[REDACTED]\";", "$password = getenv('DB_PASSWORD');")]);
        Assert.True(moved.Succeeded, "masked old_text matches: " + string.Join(" ", moved.Errors));
        Assert.True(!moved.PatchedText.Contains(secret, StringComparison.Ordinal) && moved.PatchedText.Contains("getenv", StringComparison.Ordinal), "secret removed");

        // Keeping the mask in new_text puts the original value back.
        var renamed = FixPatcher.Apply(text, [new CodeEdit("$password = \"[REDACTED]\";\nconnect($password);", "$dbPassword = \"[REDACTED]\";\nconnect($dbPassword);")]);
        Assert.True(renamed.Succeeded, "rename with mask applies");
        Assert.True(renamed.PatchedText.Contains($"$dbPassword = \"{secret}\";", StringComparison.Ordinal), "hidden value restored");
        Assert.True(!renamed.PatchedText.Contains(SourceRedactor.Mask, StringComparison.Ordinal), "mask never written");

        var invented = FixPatcher.Apply(text, [new CodeEdit("connect($password);", "connect(\"[REDACTED]\");")]);
        Assert.True(!invented.Succeeded, "a mask without a hidden value is refused");
    }

    [Test]
    public static void Applier_keeps_bom_and_crlf_backs_up_and_undoes()
    {
        using var project = new TempFolder();
        using var backups = new TempFolder();
        var path = Path.Combine(project.Path, "src", "a.php");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var original = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes("<?php\r\nrun_remote($_REQUEST['x']);\r\necho 'hi';\r\n")).ToArray();
        File.WriteAllBytes(path, original);
        var scope = new ProjectScope(project.Path);
        var applier = new FixApplier(backups.Path, new FixedTimeProvider(Now));

        var (fix, patch) = applier.Apply(scope, "src/a.php", [new CodeEdit("run_remote($_REQUEST['x']);\n", "")]);
        Assert.True(patch.Succeeded, "patched");
        var written = File.ReadAllBytes(path);
        Assert.True(written.Take(3).SequenceEqual(Encoding.UTF8.GetPreamble()), "BOM kept");
        Assert.Equal("<?php\r\necho 'hi';\r\n", Encoding.UTF8.GetString(written, 3, written.Length - 3), "CRLF kept, line removed");
        Assert.True(File.ReadAllBytes(fix.BackupPath).SequenceEqual(original), "backup holds the original");
        Assert.True(fix.BackupPath.StartsWith(backups.Path, StringComparison.OrdinalIgnoreCase), "backup is outside the project");
        Assert.True(File.Exists(Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(fix.BackupPath)!)!)!, "manifest.json")), "manifest written");

        FixApplier.Undo(fix);
        Assert.True(File.ReadAllBytes(path).SequenceEqual(original), "undo restores the original bytes");

        var (again, _) = applier.Apply(scope, "src/a.php", [new CodeEdit("run_remote($_REQUEST['x']);\n", "")]);
        File.AppendAllText(path, "// edited later\r\n");
        Assert.True(Throws<InvalidOperationException>(() => FixApplier.Undo(again)), "undo refused after a later change");
        Assert.True(Throws<InvalidOperationException>(() => applier.Apply(scope, "src/a.php", [new CodeEdit("run_remote(", "x(")])), "stale edit refused");
        Assert.True(Throws<InvalidOperationException>(() => applier.Apply(scope, "../outside.php", [new CodeEdit("a", "b")])), "path outside the project refused");
    }

    [Test]
    public static void Request_builder_redacts_and_refuses_binary_files()
    {
        using var project = new TempFolder();
        project.Write("config.php", "<?php\n$token = \"abcdefghijklmnop1234\";\nrun();\n");
        File.WriteAllBytes(Path.Combine(project.Path, "blob.bin"), [0x01, 0x02, 0x00, 0x01]);
        var scope = new ProjectScope(project.Path);
        var finding = Finding("config.php", 2);

        Assert.True(FixRequestBuilder.TryBuild(scope, finding, [finding, Finding("config.php", 3), Finding("other.php", 1)], out var request, out _), "request built");
        Assert.True(!request.RedactedFileContent.Contains("abcdefghijklmnop1234", StringComparison.Ordinal), "content redacted");
        Assert.Equal(1, request.OtherFindingsInFile.Count, "only other findings in the same file");
        Assert.True(!FixRequestBuilder.TryBuild(scope, Finding("blob.bin", 0), [], out _, out var error) && error.Contains("Binary", StringComparison.Ordinal),
            "binary files are not sent");
    }

    [Test]
    public static async Task Claude_fixer_runs_without_tools_outside_the_project_and_parses_the_answer()
    {
        using var bin = new TempFolder();
        var exe = bin.Write("claude.exe", "x");
        string? workingDirectory = null;
        var runner = new FakeProcessRunner(r =>
        {
            if (r.Arguments is ["--version"]) return FakeProcessRunner.Ok("2.1.309 (Claude Code)");
            if (r.Arguments is ["auth", "status"]) return FakeProcessRunner.Ok("{\"loggedIn\": true, \"authMethod\": \"claude.ai\"}");
            workingDirectory = r.WorkingDirectory;
            Assert.True(Directory.Exists(r.WorkingDirectory) && !Directory.EnumerateFileSystemEntries(r.WorkingDirectory).Any(), "runs in an empty folder");
            return FakeProcessRunner.Ok("""
                {"type":"result","is_error":false,"result":"","modelUsage":{"claude-sonnet-5-5":{}},
                 "structured_output":{"verdict":"fix","explanation":"Use a prepared statement.","confidence":"high",
                 "edits":[{"old_text":"a();","new_text":"b();"}]}}
                """);
        });
        var fixer = new ClaudeCodeFixer(runner, () => new ClaudeCodeSettings(true, null, "sonnet"), () => exe, new FixedTimeProvider(Now));

        var status = await fixer.GetStatusAsync(CancellationToken.None);
        Assert.Equal(EngineAvailability.Ready, status.Availability, "ready when signed in");
        Assert.Equal("2.1.309", status.Version, "version parsed");

        var finding = Finding("x.php", 1);
        var proposal = await fixer.ProposeAsync(new FixRequest(finding, "a();\n", []), CancellationToken.None);
        Assert.Equal(FixVerdict.Fix, proposal.Verdict, "verdict");
        Assert.Equal("claude-sonnet-5-5", proposal.Model, "model from usage");
        Assert.Equal(Confidence.High, proposal.Confidence, "confidence");
        Assert.Equal(new CodeEdit("a();", "b();"), proposal.Edits[0], "edit");

        var call = runner.Requests.Last();
        var args = call.Arguments.ToList();
        Assert.True(args.Contains("-p") && args[args.IndexOf("--tools") + 1] == string.Empty, "all tools disabled");
        Assert.True(args.Contains("--strict-mcp-config") && args[args.IndexOf("--setting-sources") + 1] == string.Empty, "no MCP servers or settings files");
        Assert.True(args[args.IndexOf("--model") + 1] == "sonnet", "model passed");
        Assert.True(call.StandardInput!.Contains("<<<FILE\na();\nFILE>>>", StringComparison.Ordinal), "file sent on stdin");
        Assert.True(!Directory.Exists(workingDirectory), "temporary folder removed");
    }

    [Test]
    public static async Task Claude_fixer_reports_sign_in_and_missing_cli()
    {
        using var bin = new TempFolder();
        var exe = bin.Write("claude.exe", "x");
        var runner = new FakeProcessRunner(r => r.Arguments switch
        {
            ["--version"] => FakeProcessRunner.Ok("2.1.309 (Claude Code)"),
            ["auth", "status"] => FakeProcessRunner.Ok("{\"loggedIn\": false}", 1),
            _ => FakeProcessRunner.Ok("{\"type\":\"result\",\"is_error\":true,\"result\":\"Not logged in · Please run /login\"}", 1),
        });
        var fixer = new ClaudeCodeFixer(runner, () => new ClaudeCodeSettings(true, null, null), () => exe);
        var status = await fixer.GetStatusAsync(CancellationToken.None);
        Assert.True(status.Availability == EngineAvailability.NotInstalled && status.Message!.Contains("/login", StringComparison.Ordinal), "not signed in");
        await Assert.ThrowsAsync<InvalidOperationException>(() => fixer.ProposeAsync(new FixRequest(Finding("x.php", 1), "a();", []), CancellationToken.None));

        var missing = new ClaudeCodeFixer(runner, () => new ClaudeCodeSettings(true, null, null), () => null);
        Assert.Equal(EngineAvailability.NotInstalled, (await missing.GetStatusAsync(CancellationToken.None)).Availability, "CLI not found");
        var off = new ClaudeCodeFixer(runner, () => new ClaudeCodeSettings(false, null, null), () => exe);
        Assert.Equal(EngineAvailability.Disabled, (await off.GetStatusAsync(CancellationToken.None)).Availability, "turned off");
        Assert.Equal(null, ClaudeCodeFixer.ParseLoggedIn("not json"), "unknown sign-in state");
    }

    [Test]
    public static async Task Fixing_page_proposes_applies_undoes_and_suggests_false_positives()
    {
        using var project = new TempFolder();
        var file = project.Write("app.php", "<?php\nrun_remote($_REQUEST['c']);\necho 'ok';\n");
        project.Write("lib.php", "<?php\nmd5($x);\n");
        var injected = Finding("app.php", 2);
        var weakHash = Finding("lib.php", 2);
        var fixer = new FakeFixer(r => r.Finding.Location.RelativePath == "app.php"
            ? new FixProposal(r.Finding.Id, "claude-test", FixVerdict.Fix, "Remove the injected remote command runner.",
                [new CodeEdit("run_remote($_REQUEST['c']);\n", "")], Confidence.High, Now)
            : new FixProposal(r.Finding.Id, "claude-test", FixVerdict.FalsePositive, "md5 is used as a cache key.", [], Confidence.Medium, Now));
        using var backups = new TempFolder();
        var findings = new FindingsViewModel(new EngineCatalogViewModel([]));
        var page = new FixingViewModel(findings, fixer, new FixApplier(backups.Path));
        await page.RefreshAsync();
        Assert.True(page.IsFixerReady, "fixer ready");

        findings.Load(Report(project.Path, [injected, weakHash]));
        Assert.Equal(2, page.Items.Count, "findings listed");
        await page.FixAllAsync();
        Assert.Equal(2, fixer.Calls, "Claude asked once per open finding");

        var fix = page.Items.Single(i => i.Finding.Id == injected.Id);
        var fp = page.Items.Single(i => i.Finding.Id == weakHash.Id);
        Assert.Equal(FixState.Proposed, fix.State, "fix proposed");
        Assert.True(fix.HasDiff && fix.DiffRows.Any(r => r.Kind == "Removed" && r.Text.Contains("run_remote", StringComparison.Ordinal)), "diff shows the removal");
        Assert.True(File.ReadAllText(file).Contains("run_remote", StringComparison.Ordinal), "nothing written before Apply");
        Assert.Equal(FixState.FalsePositive, fp.State, "false positive is only suggested");
        Assert.Equal(ValidationStatus.New, fp.Finding.Status, "verdict not recorded without confirmation");

        page.SelectedItem = fix;
        Assert.True(page.ApplyCommand.CanExecute(null), "apply enabled");
        await page.ApplyCommand.ExecuteAsync();
        Assert.Equal(FixState.Applied, fix.State, "applied: " + page.Message + fix.Message);
        Assert.True(!File.ReadAllText(file).Contains("run_remote", StringComparison.Ordinal), "file patched");

        await page.UndoCommand.ExecuteAsync();
        Assert.True(File.ReadAllText(file).Contains("run_remote", StringComparison.Ordinal), "undo restores the file");
        Assert.Equal(FixState.Proposed, fix.State, "proposal can be applied again");

        await page.FixAllAsync();
        Assert.Equal(2, fixer.Calls, "answered findings are not asked again");
    }

    // ---- Helpers ---------------------------------------------------------------------------------------------------

    private static bool Throws<T>(Action action) where T : Exception
    {
        try
        {
            action();
            return false;
        }
        catch (T)
        {
            return true;
        }
    }

    private static SecurityFinding Finding(string path, int line) => new(
        Guid.NewGuid(), FindingFingerprint.Compute("semgrep", "rule", path, "Issue " + line), "semgrep", "rule", "Issue " + line, "Description.",
        FindingCategory.Vulnerability, Severity.High, Confidence.Medium, FindingOrigin.Engine, new SourceLocation(path, line, line), [], [], [], null,
        ValidationStatus.New, Now);

    private static ScanReport Report(string root, IReadOnlyList<SecurityFinding> findings) => new(
        ScanReport.CurrentSchemaVersion, "0.6.0", Guid.NewGuid(), root, "pc", Now, Now.AddSeconds(5), ScanOptions.Default,
        new ScanStatistics(2, 2, 0, 0, 100, 1),
        [new EngineRunSummary("semgrep", "Semgrep CE", "Completed", "1.0", findings.Count, "ok")], [], findings);

    private sealed class FakeFixer(Func<FixRequest, FixProposal> answer) : ICodeFixer
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
