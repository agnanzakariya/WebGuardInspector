using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Scanning;
using WebGuard.Detection;
using WebGuard.Presentation.Services;
using WebGuard.Scanner;

namespace WebGuard.Tests;

public static class EngineTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 2, 8, 0, 0, TimeSpan.Zero);
    private static readonly string Root = Path.Combine(Path.GetTempPath(), "wg-root");

    private const string SemgrepJson = """
        {"version":"1.90.0","errors":[],"results":[
          {"check_id":"rules.webguard.js.eval-dynamic","path":"src/app.js",
           "start":{"line":3,"col":5},"end":{"line":3,"col":20},
           "extra":{"message":"Dynamic code evaluation with eval(). More text.","severity":"ERROR","lines":"  eval(userInput)",
                    "metadata":{"category":"security","cwe":["CWE-95: Improper Neutralization"],"confidence":"MEDIUM"}}},
          {"check_id":"style.rule","path":"src/b.js","start":{"line":1,"col":1},"end":{"line":1,"col":2},
           "extra":{"message":"x","severity":"INFO","lines":"requires login","metadata":{}}}]}
        """;

    [Test]
    public static void Semgrep_output_maps_severity_cwe_paths_and_hides_login_placeholder()
    {
        var findings = SemgrepEngine.Parse(SemgrepJson, Root, Now);
        Assert.Equal(2, findings.Count, "count");
        var eval = findings[0];
        Assert.Equal(Severity.High, eval.Severity, "ERROR -> High");
        Assert.Equal(FindingCategory.Vulnerability, eval.Category, "security category");
        Assert.Equal("CWE-95", eval.CweIds.Single(), "cwe normalized");
        Assert.Equal(Path.Combine("src", "app.js"), eval.Location.RelativePath, "relative path");
        Assert.Equal(3, eval.Location.StartLine, "line");
        Assert.Equal("Dynamic code evaluation with eval()", eval.Title, "title from first sentence");
        Assert.Equal("eval(userInput)", eval.Evidence.Single().RedactedSnippet, "snippet trimmed");
        Assert.Equal(Severity.Info, findings[1].Severity, "INFO");
        Assert.Equal(0, findings[1].Evidence.Count, "'requires login' is not evidence");

        var again = SemgrepEngine.Parse(SemgrepJson, Root, Now);
        Assert.Equal(eval.Fingerprint, again[0].Fingerprint, "fingerprint stable across runs");

        // Real Semgrep prefixes local rules with their folder; ids must not depend on where the app is installed.
        var prefixed = """
            {"results":[{"check_id":"C.Program Files.WebGuard.rules.semgrep.webguard.python.yaml-unsafe-load","path":"a.py",
              "start":{"line":1,"col":1},"end":{"line":1,"col":5},
              "extra":{"message":"yaml.load without SafeLoader can construct arbitrary Python objects.","severity":"ERROR","lines":"yaml.load(d)","metadata":{}}}]}
            """;
        var installed = SemgrepEngine.Parse(prefixed, Root, Now, [@"C:\Program Files\WebGuard\rules\semgrep"]).Single();
        Assert.Equal("webguard.python.yaml-unsafe-load", installed.RuleId, "install path stripped from rule id");
        Assert.Equal("yaml.load without SafeLoader can construct arbitrary Python objects", installed.Title, "title not cut at 'yaml.'");
        var elsewhere = SemgrepEngine.Parse(prefixed.Replace("C.Program Files.WebGuard", "D.tools.wg", StringComparison.Ordinal), Root, Now,
            [@"D:\tools\wg\rules\semgrep"]).Single();
        Assert.Equal(installed.Fingerprint, elsewhere.Fingerprint, "fingerprint independent of install folder");
    }

    [Test]
    public static async Task Semgrep_keeps_partial_results_and_surfaces_json_errors()
    {
        using var temp = new TempFolder();
        temp.Write("a.py", "yaml.load(d)");
        var exe = temp.Write("tools/semgrep.exe", "fake");
        temp.Write("rules/r.yaml", "rules: []");
        var rules = Path.Combine(temp.Path, "rules");
        var withResult = """
            {"results":[{"check_id":"r.x","path":"a.py","start":{"line":1,"col":1},"end":{"line":1,"col":5},"extra":{"message":"m","severity":"ERROR","lines":"yaml.load(d)","metadata":{}}}],
             "errors":[{"level":"error","type":"Fatal error","message":"Permission denied\nmore detail","path":"x.php"}]}
            """;
        var output = withResult;
        var runner = new FakeProcessRunner(r => FakeProcessRunner.IsVersionProbe(r) ? FakeProcessRunner.Ok("1.183.0") : FakeProcessRunner.Ok(output, exitCode: 2));
        var engine = new SemgrepEngine(runner, id => new ExternalToolOptions(id, exe, true, [rules]));
        var request = new EngineScanRequest(Guid.NewGuid(), temp.Path, [], temp.Path, TimeSpan.FromMinutes(1));

        var partial = await engine.ScanAsync(request, null, CancellationToken.None);
        Assert.True(partial.Succeeded, "partial results kept");
        Assert.Equal(1, partial.Findings.Count, "finding kept");
        Assert.True(partial.Error!.Contains("Permission denied (x.php)", StringComparison.Ordinal), "error surfaced as warning");
        Assert.True(runner.Requests.All(r => r.Environment!["PATH"].StartsWith(Path.Combine(temp.Path, "tools"), StringComparison.Ordinal)),
            "tool folder first on PATH for companion binaries");

        Assert.Equal("src/locked.js", SemgrepEngine.UnreadableFile(
            "Traceback…\nPermissionError: [Errno 13] Permission denied: \n'" + Path.Combine(temp.Path, "src", "locked.js").Replace(@"\", @"\\", StringComparison.Ordinal) + "'",
            temp.Path), "unreadable file parsed from traceback");
        Assert.Equal(null, SemgrepEngine.UnreadableFile("some other crash", temp.Path), "other failures not retried");

        output = """{"results":[],"errors":[{"type":"Invalid rule","message":"rule r.x: bad pattern"}]}""";
        var failed = await engine.ScanAsync(request, null, CancellationToken.None);
        Assert.True(!failed.Succeeded, "fatal without results");
        Assert.True(failed.Error!.Contains("bad pattern", StringComparison.Ordinal), "JSON error message shown");
    }

    [Test]
    public static void Gitleaks_output_is_redacted_even_without_redact_flag()
    {
        var json = """
            [{"Description":"AWS Access Key","StartLine":2,"EndLine":2,"StartColumn":7,"EndColumn":26,
              "Match":"key = AKIAIOSFODNN7EXAMPLE","Secret":"AKIAIOSFODNN7EXAMPLE",
              "File":"PLACEHOLDER","RuleID":"aws-access-token","Entropy":3.68}]
            """.Replace("PLACEHOLDER", Path.Combine(Root, "config", ".env").Replace("\\", "\\\\"), StringComparison.Ordinal);
        var f = GitleaksEngine.Parse(json, Root, Now).Single();
        Assert.Equal(FindingCategory.Secret, f.Category, "category");
        Assert.Equal(Path.Combine("config", ".env"), f.Location.RelativePath, "absolute path made relative");
        Assert.Equal("CWE-798", f.CweIds.Single(), "cwe");
        var snippet = f.Evidence.Single().RedactedSnippet!;
        Assert.True(!snippet.Contains("AKIAIOSFODNN7EXAMPLE", StringComparison.Ordinal), "raw secret never stored");
        Assert.True(snippet.StartsWith("key = AKIA*", StringComparison.Ordinal), "prefix kept for triage");
        Assert.True(GitleaksEngine.Parse("", Root, Now).Count == 0, "empty report");

        var partial = GitleaksEngine.Parse("""[{"RuleID":"github-pat","File":"a.js","Match":"ghp_WGI5...","Secret":"ghp_WGI5..."}]""", Root, Now).Single();
        Assert.Equal("ghp_WGI5...", partial.Evidence.Single().RedactedSnippet, "partially redacted value is not masked again");
        Assert.Equal("Hardcoded secret: github-pat", partial.Title, "short title");
    }

    [Test]
    public static void Osv_output_groups_aliases_and_uses_cvss_and_fixed_versions()
    {
        var json = """
            {"results":[{"source":{"path":"package-lock.json","type":"lockfile"},"packages":[{
              "package":{"name":"lodash","version":"4.17.15","ecosystem":"npm"},
              "vulnerabilities":[
                {"id":"GHSA-p6mc-m468-83gw","aliases":["CVE-2020-8203"],"summary":"Prototype Pollution in lodash",
                 "affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"4.17.19"}]}]}],
                 "database_specific":{"severity":"HIGH","cwe_ids":["CWE-1321"]}},
                {"id":"CVE-2020-8203","aliases":["GHSA-p6mc-m468-83gw"]}],
              "groups":[{"ids":["GHSA-p6mc-m468-83gw","CVE-2020-8203"],"max_severity":"7.4"}]}]}]}
            """;
        var f = OsvScannerEngine.Parse(json, Root, Now).Single();
        Assert.Equal("GHSA-p6mc-m468-83gw", f.RuleId, "primary id");
        Assert.Equal(Severity.High, f.Severity, "CVSS 7.4 -> High");
        Assert.Equal(FindingCategory.VulnerableDependency, f.Category, "category");
        Assert.True(f.AdvisoryIds.Contains("CVE-2020-8203"), "CVE alias kept");
        Assert.Equal("CWE-1321", f.CweIds.Single(), "cwe");
        Assert.True(f.Remediation!.Contains("4.17.19", StringComparison.Ordinal), "fix version in remediation");
        Assert.Equal("package-lock.json", f.Location.RelativePath, "lockfile location");
    }

    [Test]
    public static void Yara_ndjson_with_array_or_object_meta_is_parsed()
    {
        var output = """
            {"path":"web/shell.php","rules":[{"identifier":"php_webshell_eval_input","namespace":"default",
              "meta":[["title","PHP web shell"],["severity","critical"],["category","malware"]]}]}
            {"path":"web/clean.php","rules":[]}
            {"path":"tools/x.ps1","rules":[{"identifier":"powershell_download_execute","meta":{"category":"suspicious"}}]}
            """;
        var findings = YaraXEngine.Parse(output, Root, Now);
        Assert.Equal(2, findings.Count, "two matches");
        Assert.Equal("PHP web shell", findings[0].Title, "title from meta");
        Assert.Equal(Severity.Critical, findings[0].Severity, "severity from meta");
        Assert.Equal(FindingCategory.Malware, findings[0].Category, "malware category");
        Assert.Equal(FindingCategory.SuspiciousPattern, findings[1].Category, "suspicious category");
        Assert.Equal(Severity.High, findings[1].Severity, "default severity for suspicious");
    }

    [Test]
    public static void Version_switches_select_the_right_cli_syntax()
    {
        Assert.True(GitleaksEngine.UsesDirCommand("8.21.2"), "8.21 uses dir");
        Assert.True(!GitleaksEngine.UsesDirCommand("8.18.4"), "8.18 uses detect");
        Assert.True(OsvScannerEngine.IsV2("2.0.1"), "v2");
        Assert.True(!OsvScannerEngine.IsV2("1.9.2"), "v1");
    }

    [Test]
    public static async Task Engine_status_reports_missing_disabled_relative_and_ready()
    {
        using var temp = new TempFolder();
        var exe = temp.Write("tools/semgrep.exe", "fake");
        var runner = new FakeProcessRunner(_ => FakeProcessRunner.Ok("1.90.0"));

        var disabled = await new SemgrepEngine(runner, id => new ExternalToolOptions(id, exe, false, [], "Off.")).GetStatusAsync(CancellationToken.None);
        Assert.Equal(EngineAvailability.Disabled, disabled.Availability, "disabled");
        Assert.Equal("Off.", disabled.Message, "reason shown");

        var relative = await new SemgrepEngine(runner, id => new ExternalToolOptions(id, "tools\\semgrep.exe", true, [])).GetStatusAsync(CancellationToken.None);
        Assert.Equal(EngineAvailability.Error, relative.Availability, "relative path rejected");

        var missing = await new SemgrepEngine(runner, id => new ExternalToolOptions(id, Path.Combine(temp.Path, "nope.exe"), true, []))
            .GetStatusAsync(CancellationToken.None);
        Assert.Equal(EngineAvailability.Error, missing.Availability, "configured but missing");

        var rules = Path.Combine(temp.Path, "rules");
        temp.Write("rules/r.yaml", "rules: []");
        var ready = await new SemgrepEngine(runner, id => new ExternalToolOptions(id, exe, true, [rules])).GetStatusAsync(CancellationToken.None);
        Assert.Equal(EngineAvailability.Ready, ready.Availability, "ready");
        Assert.Equal("1.90.0", ready.Version, "version parsed");
        Assert.Equal(exe, ready.ExecutablePath, "absolute path reported");
    }

    [Test]
    public static async Task Scanner_runs_engines_filters_out_of_scope_findings_and_survives_failures()
    {
        using var temp = new TempFolder();
        temp.Write("src/app.js", "eval(userInput)");
        temp.Write("node_modules/lib/x.js", "eval(a)");
        var semgrepExe = temp.Write("tools/semgrep.exe", "fake");
        var yrExe = temp.Write("tools/yr.exe", "fake");
        temp.Write("rules/r.yaml", "rules: []");
        var rules = Path.Combine(temp.Path, "rules");
        var json = """
            {"results":[
              {"check_id":"r.eval","path":"src/app.js","start":{"line":1,"col":1},"end":{"line":1,"col":5},"extra":{"message":"eval","severity":"ERROR","lines":"eval(userInput)","metadata":{}}},
              {"check_id":"r.eval","path":"src/app.js","start":{"line":1,"col":1},"end":{"line":1,"col":5},"extra":{"message":"eval","severity":"ERROR","lines":"eval(userInput)","metadata":{}}},
              {"check_id":"r.eval","path":"node_modules/lib/x.js","start":{"line":1,"col":1},"end":{"line":1,"col":5},"extra":{"message":"eval","severity":"ERROR","lines":"eval(a)","metadata":{}}},
              {"check_id":"r.eval","path":"../outside.js","start":{"line":1,"col":1},"end":{"line":1,"col":5},"extra":{"message":"eval","severity":"ERROR","lines":"x","metadata":{}}}]}
            """;
        var runner = new FakeProcessRunner(r =>
            FakeProcessRunner.IsVersionProbe(r) ? FakeProcessRunner.Ok("1.0.0")
            : r.ExecutablePath == semgrepExe ? FakeProcessRunner.Ok(json, exitCode: 1)
            : new ProcessRunResult(2, string.Empty, new string('.', 2000) + "\nrule compile error", TimeSpan.Zero, false, false));
        ExternalToolOptions Options(string id) => id switch
        {
            SemgrepEngine.Id => new(id, semgrepExe, true, [rules]),
            YaraXEngine.Id => new(id, yrExe, true, [rules]),
            _ => new(id, null, false, [], "Off."),
        };

        var scanner = new LocalFolderScanner(SecurityEngineCatalog.CreateDefault(runner, Options));
        var report = await scanner.ScanAsync(temp.Path, ScanOptions.Default, null, CancellationToken.None);

        var finding = report.Findings.Single();
        Assert.Equal(Path.Combine("src", "app.js"), finding.Location.RelativePath, "only in-scope finding, duplicates merged");
        var semgrep = report.Engines.Single(e => e.EngineId == SemgrepEngine.Id);
        Assert.Equal("Completed", semgrep.Outcome, "semgrep completed");
        Assert.Equal(1, semgrep.FindingCount, "finding count");
        Assert.True(semgrep.Message!.Contains("outside the inventory", StringComparison.Ordinal), "dropped findings reported");
        var yara = report.Engines.Single(e => e.EngineId == YaraXEngine.Id);
        Assert.Equal("Failed", yara.Outcome, "yara failure recorded");
        Assert.True(yara.Message!.Contains("rule compile error", StringComparison.Ordinal), "stderr surfaced");
        Assert.Equal("Disabled", report.Engines.Single(e => e.EngineId == GitleaksEngine.Id).Outcome, "disabled engine skipped");

        var scanCall = runner.Requests.First(r => r.ExecutablePath == semgrepExe && !FakeProcessRunner.IsVersionProbe(r));
        Assert.True(scanCall.Arguments.Contains("--metrics=off"), "metrics off");
        Assert.Equal(temp.Path, scanCall.Arguments[^1], "scans the selected root");
        Assert.True(!Directory.Exists(scanCall.WorkingDirectory), "engine work directory cleaned up");
    }

    [Test]
    public static async Task Gitleaks_reads_report_file_and_deletes_it()
    {
        using var temp = new TempFolder();
        temp.Write("app/.env", "TOKEN=x");
        var exe = temp.Write("tools/gitleaks.exe", "fake");
        string? reportPath = null;
        var runner = new FakeProcessRunner(r =>
        {
            if (FakeProcessRunner.IsVersionProbe(r)) return FakeProcessRunner.Ok("8.21.2");
            var args = r.Arguments.ToList();
            reportPath = args[args.IndexOf("--report-path") + 1];
            File.WriteAllText(reportPath, """[{"RuleID":"generic-api-key","Description":"Generic API Key","File":"app/.env","StartLine":1,"EndLine":1,"Match":"TOKEN=REDACTED","Secret":"REDACTED"}]""");
            return FakeProcessRunner.Ok(string.Empty);
        });
        var scanner = new LocalFolderScanner([new GitleaksEngine(runner, id => new ExternalToolOptions(id, exe, true, []))]);
        var report = await scanner.ScanAsync(temp.Path, ScanOptions.Default, null, CancellationToken.None);

        Assert.Equal(FindingCategory.Secret, report.Findings.Single().Category, "secret finding");
        Assert.Equal("dir", runner.Requests[^1].Arguments[0], "modern dir command");
        Assert.True(runner.Requests[^1].Arguments.Contains("--redact=80"), "partial redaction on modern gitleaks");
        Assert.True(reportPath is not null && !File.Exists(reportPath), "report file removed");
    }

    [Test]
    public static async Task Process_runner_rejects_relative_paths_captures_output_and_times_out()
    {
        var runner = new ExternalProcessRunner();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            runner.RunAsync(new ProcessRunRequest("cmd.exe", [], Path.GetTempPath(), TimeSpan.FromSeconds(5), 1024), CancellationToken.None));
        if (!OperatingSystem.IsWindows()) return;

        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        var ok = await runner.RunAsync(new ProcessRunRequest(cmd, ["/c", "echo hello& exit 3"], Path.GetTempPath(), TimeSpan.FromSeconds(10), 1024),
            CancellationToken.None);
        Assert.Equal(3, ok.ExitCode, "exit code");
        Assert.True(ok.StandardOutput.Contains("hello", StringComparison.Ordinal), "stdout captured");

        var slow = await runner.RunAsync(new ProcessRunRequest(cmd, ["/c", "ping -n 10 127.0.0.1"], Path.GetTempPath(), TimeSpan.FromMilliseconds(300), 1 << 20),
            CancellationToken.None);
        Assert.True(slow.TimedOut, "timed out");

        var capped = await runner.RunAsync(new ProcessRunRequest(cmd, ["/c", "for /L %i in (1,1,200) do @echo 0123456789"], Path.GetTempPath(), TimeSpan.FromSeconds(10), 100),
            CancellationToken.None);
        Assert.True(capped.OutputTruncated, "output capped");
    }

    [Test]
    public static async Task Process_runner_kills_workers_that_outlive_the_wrapper()
    {
        if (!OperatingSystem.IsWindows()) return;
        // Like semgrep.exe: the started process exits at once and leaves a worker running with its output handle.
        var started = DateTime.Now.AddSeconds(-1);
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = await new ExternalProcessRunner().RunAsync(
            new ProcessRunRequest(cmd, ["/c", "start /b ping -n 60 127.0.0.1 >nul & exit 0"], Path.GetTempPath(), TimeSpan.FromSeconds(2), 1 << 20),
            CancellationToken.None);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), "runner returns soon after its timeout");
        var orphans = System.Diagnostics.Process.GetProcessesByName("PING").Where(p =>
        {
            try { return p.StartTime > started; } catch (InvalidOperationException) { return false; }
        }).ToArray();
        Assert.True(result.TimedOut || result.ExitCode == 0, "run finished");
        Assert.Equal(0, orphans.Length, "worker started by the tool was terminated");
    }

    [Test]
    public static void Locator_only_returns_absolute_exe_paths()
    {
        using var temp = new TempFolder();
        temp.Write("a/tool.cmd", "@echo pwned");
        var exe = temp.Write("b/tool.exe", "fake");
        var dirs = new[] { "relative-dir", Path.Combine(temp.Path, "a"), Path.Combine(temp.Path, "b") };
        var found = ExecutableLocator.Find(["tool"], dirs);
        if (OperatingSystem.IsWindows()) Assert.Equal(Path.GetFullPath(exe), found, "exe found, cmd ignored");
        Assert.Equal(null, ExecutableLocator.Find(["missing"], dirs), "missing tool");
    }

    [Test]
    public static void Settings_gate_network_engines_behind_consent()
    {
        var settings = new AppSettings { DisabledEngines = ["yara-x"], EngineExecutables = new Dictionary<string, string> { ["semgrep"] = @"C:\t\semgrep.exe" } };
        Assert.True(!settings.ToolOptions("osv-scanner").Enabled, "osv off without consent");
        Assert.True((settings with { AllowExternalIntelligence = true }).ToolOptions("osv-scanner").Enabled, "osv on with consent");
        Assert.True(!settings.ToolOptions("yara-x").Enabled, "user-disabled engine");
        Assert.Equal(@"C:\t\semgrep.exe", settings.ToolOptions("semgrep").ExecutablePath, "configured path");
        Assert.Equal(null, settings.ToolOptions("gitleaks").ExecutablePath, "auto-detect");
    }
}
