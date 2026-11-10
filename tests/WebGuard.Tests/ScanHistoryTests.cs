using System.Text;
using WebGuard.Core.AI;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Fixing;
using WebGuard.Core.Scanning;
using WebGuard.Presentation.Services;
using WebGuard.Presentation.ViewModels;
using WebGuard.Scanner;

namespace WebGuard.Tests;

/// <summary>Scan sessions kept across restarts, their activity log, the résumé page and the PDF report.</summary>
public static class ScanHistoryTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 10, 9, 0, 0, TimeSpan.Zero);

    [Test]
    public static async Task Sessions_and_activities_survive_a_restart_without_the_file_inventory()
    {
        using var folder = new TempFolder();
        var first = Report(@"C:\sites\shop", Now, [Finding("a.php", 3)]);
        using (var store = new JsonScanHistoryStore(folder.Path, capacity: 2))
        {
            await store.AddAsync(first);
            await store.AppendActivityAsync(first.ScanId, new SessionActivity(Now.AddMinutes(1), SessionActivityKind.Verdict, "Marked Confirmed: Issue"));
            await store.AppendActivityAsync(Guid.NewGuid(), new SessionActivity(Now, SessionActivityKind.Verdict, "unknown session is ignored"));
        }

        using (var reopened = new JsonScanHistoryStore(folder.Path, capacity: 2))
        {
            var sessions = await reopened.GetRecentAsync(10);
            Assert.True(sessions.Single() is { Findings.Count: 1, Files.Count: 0, Statistics.FileCount: 3 } s && s.ScanId == first.ScanId,
                "report kept with findings and statistics, inventory dropped");
            Assert.Equal("Marked Confirmed: Issue", (await reopened.GetActivitiesAsync(first.ScanId)).Single().Summary, "activity kept");

            await reopened.AddAsync(Report(@"C:\sites\blog", Now.AddHours(1), []));
            await reopened.AddAsync(Report(@"C:\sites\shop", Now.AddHours(2), []));
            var kept = await reopened.GetRecentAsync(10);
            Assert.True(kept.Count == 2 && kept.All(r => r.ScanId != first.ScanId) && kept[0].StartedAtUtc > kept[1].StartedAtUtc,
                "oldest session removed beyond capacity, newest first");
            Assert.Equal(2, Directory.EnumerateFiles(folder.Path, "session-*.json").Count(), "one file per kept session");
        }
    }

    [Test]
    public static async Task Verdicts_and_fixes_are_recorded_in_the_session_and_shown_as_a_resume()
    {
        using var project = new TempFolder();
        using var backups = new TempFolder();
        project.Write("app.php", "<?php\nrun_remote($_REQUEST['c']);\necho 'ok';\n");
        var store = new InMemoryScanHistoryStore();
        var log = new SessionActivityLog(store, new FixedTimeProvider(Now));
        var finding = Finding("app.php", 2);
        var report = Report(project.Path, Now, [finding]);
        await store.AddAsync(report);
        await store.AppendActivityAsync(report.ScanId, new SessionActivity(Now, SessionActivityKind.Scan, "Scanned 3 files", project.Path));

        var analyst = new Analyst();
        var findings = new FindingsViewModel(new EngineCatalogViewModel([]), analyst, activityLog: log);
        var fixer = new Fixer(r => new FixProposal(r.Finding.Id, "claude-test", FixVerdict.Fix, "Remove the remote command runner.",
            [new CodeEdit("run_remote($_REQUEST['c']);\n", "")], Confidence.High, Now));
        var page = new FixingViewModel(findings, fixer, new FixApplier(backups.Path));
        await page.RefreshAsync();
        findings.Load(report);
        findings.SelectedFinding = findings.Findings.Single();
        await findings.AnalyzeSelectedAsync();
        analyst.Fail = true;
        await findings.AnalyzeSelectedAsync(askModel: true);
        await page.FixAllAsync();
        page.SelectedItem = page.Items.Single();
        await page.ApplyCommand.ExecuteAsync();
        await page.UndoCommand.ExecuteAsync();

        var kinds = (await store.GetActivitiesAsync(report.ScanId)).Select(a => a.Kind).ToArray();
        Assert.True(kinds.SequenceEqual([SessionActivityKind.Scan, SessionActivityKind.AiAnalysis, SessionActivityKind.AiAnalysis, SessionActivityKind.FixProposed,
                SessionActivityKind.FixApplied, SessionActivityKind.FixUndone]),
            "scan, analysis, failed analysis, proposal, apply and undo recorded in order: " + string.Join(", ", kinds));
        var all = await store.GetActivitiesAsync(report.ScanId);
        Assert.True(all[1] is { Fingerprint: var fp, Sections: [{ Title: "Summary", Text: "Untrusted input reaches a shell." }, { Title: "Why it matters" },
                { Title: var remediationTitle, Text: "Use escapeshellarg().", Style: ActivitySectionStyle.Code }] } && fp == finding.Fingerprint &&
                    remediationTitle.StartsWith("Proposed remediation", StringComparison.Ordinal), "the whole AI analysis is kept, linked to its finding");
        Assert.True(all[2].Summary.StartsWith("AI analysis failed", StringComparison.Ordinal) && all[2].Detail == "model crashed", "a failed analysis is logged too");
        var proposed = all[3].Sections!;
        Assert.True(proposed.Any(x => x is { Title: "Explanation", Text: "Remove the remote command runner." }) &&
                    proposed.Single(x => x.Style == ActivitySectionStyle.Diff).Text.Contains("-run_remote(", StringComparison.Ordinal), "explanation and diff of the proposal");
        var applied = all[4];
        Assert.True(applied.Location == "app.php:2" && applied.Sections!.Any(x => x.Title.StartsWith("Backup", StringComparison.Ordinal)) &&
                    applied.Sections!.Any(x => x is { Title: "Applied change", Style: ActivitySectionStyle.Diff }), "where and how the fix was applied");

        var history = new ScanHistoryViewModel(store, log, new FakeSaveDialog(null), null, null, new PdfReportExporter(compress: false), new JsonReportExporter());
        await history.RefreshAsync();
        Assert.True(history.Detail is { HasTimeline: true } d && d.Timeline.Count == 6 && d.Timeline[0].KindText == "Fix undone" &&
                    d.Timeline.Single(t => t.KindText == "Fix applied").HasSections,
            "résumé of the selected session, newest activity first");
        Assert.True(history.Detail!.ActivityText.Contains("1 fix request(s)", StringComparison.Ordinal) && history.Detail.ActivityText.Contains("1 applied", StringComparison.Ordinal),
            "activity counts");

        using var output = new TempFolder();
        var pdfPath = Path.Combine(output.Path, "session.pdf");
        await history.ExportAsync(pdf: true, pdfPath);
        var pdf = Encoding.Latin1.GetString(File.ReadAllBytes(pdfPath));
        Assert.True(pdf.StartsWith("%PDF-1.4", StringComparison.Ordinal) && pdf.TrimEnd().EndsWith("%%EOF", StringComparison.Ordinal), "a PDF file");
        Assert.True(pdf.Contains("(Security scan report)", StringComparison.Ordinal) && pdf.Contains("(Fix applied)", StringComparison.Ordinal) &&
                    pdf.Contains(@"(AI analyses and remediation \(3\))", StringComparison.Ordinal) && pdf.Contains("(Untrusted input reaches a shell.)", StringComparison.Ordinal) &&
                    pdf.Contains("(Remove the remote command runner.)", StringComparison.Ordinal) && pdf.Contains(@"(-run_remote\($_REQUEST['c']\);)", StringComparison.Ordinal),
            "report with the full AI analysis, the remediation and the diff");
        Assert.True(history.Detail!.Timeline[0].KindText == "Export" && history.Message.Contains(pdfPath, StringComparison.Ordinal), "the export itself is recorded");
    }

    [Test]
    public static void Pdf_writer_encodes_text_wraps_and_paginates()
    {
        Assert.Equal("(a\\(b\\) \\\\ \\227 caf\\351 ?)", PdfDocumentBuilder.PdfString("a(b) \\ — café 漢"), "escapes, WinAnsi bytes as octal, unknown as ?");
        var lines = PdfDocumentBuilder.Wrap("short words here and a very-long-path/that/cannot/break/at/spaces/at/all.php", PdfFont.Regular, 10, 120);
        Assert.True(lines.Count > 2 && lines.All(l => PdfDocumentBuilder.Width(l, PdfFont.Regular, 10) <= 120.01), "every line fits");

        var builder = new PdfDocumentBuilder { FooterText = "footer" };
        builder.Table([new("#", 30), new("Text", 0)], Enumerable.Range(1, 200).Select(i => (IReadOnlyList<PdfCell>)[new(i.ToString(System.Globalization.CultureInfo.InvariantCulture)), new("Row " + i)]));
        using var ms = new MemoryStream();
        builder.Save(ms, "t", Now, compress: false);
        var text = Encoding.Latin1.GetString(ms.ToArray());
        var pages = System.Text.RegularExpressions.Regex.Match(text, @"/Count (\d+)").Groups[1].Value;
        Assert.True(int.Parse(pages, System.Globalization.CultureInfo.InvariantCulture) >= 4 && text.Contains("(Page 1 of " + pages + ")", StringComparison.Ordinal),
            "long tables continue on new pages with page numbers");
        Assert.True(text.Split("(Text)").Length - 1 == int.Parse(pages, System.Globalization.CultureInfo.InvariantCulture), "header repeated on every page");
    }

    // ---- Helpers ---------------------------------------------------------------------------------------------------

    private static SecurityFinding Finding(string path, int line) => new(
        Guid.NewGuid(), FindingFingerprint.Compute("semgrep", "rce", path, "x" + line), "semgrep", "rce", "Remote command execution", "d",
        FindingCategory.Vulnerability, Severity.High, Confidence.High, FindingOrigin.Engine, new SourceLocation(path, line, line), [], ["CWE-78"], [], null,
        ValidationStatus.New, Now);

    private static ScanReport Report(string root, DateTimeOffset started, IReadOnlyList<SecurityFinding> findings) => new(
        ScanReport.CurrentSchemaVersion, "1.0.1", Guid.NewGuid(), root, "pc", started, started.AddSeconds(4), ScanOptions.Default,
        new ScanStatistics(3, 3, 0, 0, 300, 0),
        [new EngineRunSummary("semgrep", "Semgrep CE", "Completed", "1.0", findings.Count, "ok")],
        [new FileInventoryItem("a.php", ".php", 100, started, new string('a', 64), FileScanStatus.Hashed, 0, null)],
        findings);

    private sealed class Analyst : IAiSecurityAnalyst
    {
        public bool Fail { get; set; }
        public string DisplayName => "fake";
        public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) => Task.FromResult(new EngineStatus(EngineAvailability.Ready, "1", null, "ok"));

        public Task<AiAnalysis> AnalyzeAsync(FindingContext context, CancellationToken cancellationToken) => Fail
            ? throw new HttpRequestException("model crashed")
            : Task.FromResult(new AiAnalysis(context.Finding.Id, "qwen-test", "Untrusted input reaches a shell.", "Remote code execution.",
                "Use escapeshellarg().", Confidence.High, false, Now));
    }

    private sealed class Fixer(Func<FixRequest, FixProposal> answer) : ICodeFixer
    {
        public string DisplayName => "fake";
        public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) => Task.FromResult(new EngineStatus(EngineAvailability.Ready, "1", null, "ok"));
        public Task<FixProposal> ProposeAsync(FixRequest request, CancellationToken cancellationToken) => Task.FromResult(answer(request));
    }
}
