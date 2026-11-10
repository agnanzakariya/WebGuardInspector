using System.Globalization;
using WebGuard.Core;
using WebGuard.Core.Findings;
using WebGuard.Core.Reporting;
using WebGuard.Core.Scanning;

namespace WebGuard.Scanner;

/// <summary>
/// PDF report of a scan session: session details, summary, engines, findings (redacted, by severity) and the activity
/// timeline, followed by the full AI analyses and fixes (explanation, diff, backup). Secrets are redacted; source code
/// appears only as the changed lines of fix diffs.
/// </summary>
public sealed class PdfReportExporter(TimeZoneInfo? timeZone = null, TimeProvider? timeProvider = null, bool compress = true)
    : IReportExporter, ISessionReportExporter
{
    private static readonly PdfColor Band = PdfColor.FromHex("#1E3A8A");
    private readonly TimeZoneInfo _zone = timeZone ?? TimeZoneInfo.Local;
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    public string FormatName => "PDF";
    public string FileExtension => ".pdf";

    public Task ExportAsync(ScanReport report, Stream destination, CancellationToken cancellationToken) =>
        ExportAsync(report, [], destination, cancellationToken);

    public Task ExportAsync(ScanReport report, IReadOnlyList<SessionActivity> activities, Stream destination, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(activities);
        ArgumentNullException.ThrowIfNull(destination);
        var pdf = Build(report, activities);
        pdf.Save(destination, "Azura security scan report — " + Path.GetFileName(report.RootFolder.TrimEnd('\\', '/')), _time.GetUtcNow(), compress);
        return Task.CompletedTask;
    }

    public static PdfColor SeverityColor(Severity severity) => severity switch
    {
        Severity.Critical => PdfColor.FromHex("#B91C1C"),
        Severity.High => PdfColor.FromHex("#C2410C"),
        Severity.Medium => PdfColor.FromHex("#A16207"),
        Severity.Low => PdfColor.FromHex("#1D4ED8"),
        _ => PdfColor.Gray,
    };

    private PdfDocumentBuilder Build(ScanReport report, IReadOnlyList<SessionActivity> activities)
    {
        var pdf = new PdfDocumentBuilder();
        var project = Path.GetFileName(report.RootFolder.TrimEnd('\\', '/'));
        var generated = Local(_time.GetUtcNow());
        pdf.FooterText = $"{AppInfo.Name} {AppInfo.Version} · {project} · generated {generated}";
        pdf.TitleBand("Security scan report", $"{AppInfo.Name} {AppInfo.Version} · {project}", Band);

        var st = report.Statistics;
        var sev = SeveritySummary.From(report.Findings);
        var completed = report.Engines.Count(e => e.Outcome == "Completed");
        var done = SessionActivitySummary.From(activities);

        pdf.Heading("Session");
        pdf.KeyValues(
        [
            ("Folder", report.RootFolder, null),
            ("Scan ID", report.ScanId.ToString("D", CultureInfo.InvariantCulture), null),
            ("Started", Local(report.StartedAtUtc), null),
            ("Finished", Local(report.FinishedAtUtc) + string.Create(CultureInfo.InvariantCulture, $" ({report.Duration.TotalSeconds:0.0} s)"), null),
            ("Machine", report.MachineName, null),
            ("Scanned with", $"{AppInfo.Name} {report.ToolVersion}", null),
            ("Result", report.Findings.Count > 0 ? $"{report.Findings.Count} finding(s)" : completed > 0 ? "Clean: no findings" : "Not analysed: no engine completed",
                report.Findings.Count > 0 ? SeverityColor(sev.Critical > 0 ? Severity.Critical : sev.High > 0 ? Severity.High : Severity.Medium) : PdfColor.FromHex("#15803D")),
        ]);

        pdf.Heading("Summary");
        pdf.StatTiles(
        [
            (Count(st.FileCount), "Files", Band),
            (Count(report.Findings.Count), "Findings", PdfColor.Black),
            (Count(sev.Critical), "Critical", SeverityColor(Severity.Critical)),
            (Count(sev.High), "High", SeverityColor(Severity.High)),
            (Count(sev.Medium), "Medium", SeverityColor(Severity.Medium)),
            (Count(sev.Low + sev.Info), "Low / Info", SeverityColor(Severity.Low)),
        ]);
        var statuses = report.Findings.GroupBy(f => f.Status).OrderBy(g => g.Key).Select(g => $"{g.Count()} {g.Key}");
        pdf.KeyValues(
        [
            ("Inventory", string.Create(CultureInfo.InvariantCulture,
                $"{st.FileCount:N0} files, {st.HashedCount:N0} hashed (SHA-256), {st.SkippedCount:N0} skipped, {st.ErrorCount:N0} errors, {Bytes(st.TotalBytes)}, {st.ExcludedDirectoryCount:N0} excluded folders"), null),
            ("Engines", $"{completed} of {report.Engines.Count} completed", null),
            ("Finding status", report.Findings.Count == 0 ? "—" : string.Join(", ", statuses), null),
            ("Activity", $"{done.Verdicts} verdict(s), {done.AiAnalyses} AI analysis(es), {done.FixesProposed} fix request(s), " +
                         $"{done.FixesApplied} fix(es) applied, {done.FixesUndone} undone, {done.Exports} export(s)", null),
        ]);
        pdf.Paragraph("Findings come from deterministic engines. AI analyses and AI fix proposals are hypotheses that a person reviewed; " +
                      "code was only changed where a fix is listed as applied. Evidence and secrets are redacted; source code appears only as the " +
                      "changed lines of fix diffs.",
            8, PdfColor.Gray);

        pdf.Heading("Security engines");
        pdf.Table(
            [new("Engine", 105), new("Outcome", 70), new("Version", 55), new("Findings", 48), new("Details", 0)],
            report.Engines.Select(e => (IReadOnlyList<PdfCell>)
            [
                new(e.DisplayName, Font: PdfFont.Bold),
                new(e.Outcome, e.Outcome switch { "Completed" => PdfColor.FromHex("#15803D"), "Failed" => SeverityColor(Severity.Critical), _ => PdfColor.Gray }),
                new(e.Version ?? "—"),
                new(e.FindingCount.ToString(CultureInfo.InvariantCulture)),
                new(e.Message ?? string.Empty, PdfColor.Gray),
            ]), maxLinesPerCell: 3);

        pdf.Heading(string.Create(CultureInfo.InvariantCulture, $"Findings ({report.Findings.Count})"));
        if (report.Findings.Count == 0)
        {
            pdf.Paragraph(completed > 0 ? "No findings." : "No security engine completed, so this scan does not show that the project is clean.");
        }
        else
        {
            var number = 0;
            pdf.Table(
                [new("#", 24), new("Severity", 52), new("Status", 62), new("Issue", 0), new("Location", 140), new("Engine", 58)],
                report.Findings
                    .OrderByDescending(f => f.Severity)
                    .ThenBy(f => f.Location.RelativePath, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(f => f.Location.StartLine)
                    .Select(f => (IReadOnlyList<PdfCell>)
                    [
                        new((++number).ToString(CultureInfo.InvariantCulture), PdfColor.Gray),
                        new(f.Severity.ToString(), SeverityColor(f.Severity), PdfFont.Bold),
                        new(f.Status.ToString()),
                        new(SourceRedactor.Redact(f.Title), Note: Refs(f)),
                        new(f.Location.ToString()),
                        new(f.EngineId, PdfColor.Gray),
                    ]), maxLinesPerCell: 4);
        }

        pdf.Heading(string.Create(CultureInfo.InvariantCulture, $"Session activity ({activities.Count})"));
        if (activities.Count == 0)
        {
            pdf.Paragraph("No activity was recorded for this session.");
        }
        else
        {
            pdf.Table(
                [new("Time", 84), new("Activity", 72), new("What happened", 0)],
                activities.OrderBy(a => a.AtUtc).Select(a => (IReadOnlyList<PdfCell>)
                [
                    new(Local(a.AtUtc, "dd MMM HH:mm:ss"), PdfColor.Gray),
                    new(Label(a.Kind), KindColor(a.Kind), PdfFont.Bold),
                    new(a.Summary + (a.Sections is { Count: > 0 } ? "  (details below)" : string.Empty),
                        Note: string.Join(" · ", new[] { a.Location, a.Detail }.Where(s => !string.IsNullOrWhiteSpace(s)))),
                ]), maxLinesPerCell: 5);
        }

        AddDetails(pdf, report, activities);
        return pdf;
    }

    /// <summary>
    /// Full results in the order they happened: every AI analysis (summary, why it matters, proposed remediation) and every
    /// fix (explanation, diff, backup, command), with the finding and the scanner's own remediation advice.
    /// </summary>
    private void AddDetails(PdfDocumentBuilder pdf, ScanReport report, IReadOnlyList<SessionActivity> activities)
    {
        var detailed = activities.Where(a => a.Sections is { Count: > 0 }).OrderBy(a => a.AtUtc).ToList();
        if (detailed.Count == 0) return;
        var findings = report.Findings.GroupBy(f => f.Fingerprint, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        var advised = new HashSet<string>(StringComparer.Ordinal);

        pdf.NewPage();
        pdf.Heading(string.Create(CultureInfo.InvariantCulture, $"AI analyses and remediation ({detailed.Count})"));
        pdf.Paragraph("Full results of the AI analyses and fixes in this session, in the order they happened. AI output is a hypothesis; " +
                      "only changes listed as \"Fix applied\" were written to the project. Diffs show the changed lines with secrets redacted.",
            8, PdfColor.Gray);

        foreach (var a in detailed)
        {
            var finding = a.Fingerprint is not null && findings.TryGetValue(a.Fingerprint, out var f) ? f : null;
            var meta = string.Join(" · ", new[]
            {
                Local(a.AtUtc),
                finding is null ? a.Location : $"{finding.Severity} · {finding.EngineId} / {finding.RuleId} · {finding.Location}",
                a.Detail,
            }.Where(s => !string.IsNullOrWhiteSpace(s)));
            pdf.EntryHeader(Label(a.Kind), KindColor(a.Kind) == PdfColor.Black ? PdfColor.FromHex("#475569") : KindColor(a.Kind), a.Summary, meta);

            // The scanner's advice once per finding, next to the first AI result for it.
            if (finding is { Remediation: { Length: > 0 } advice } && advised.Add(finding.Fingerprint))
            {
                pdf.Label("Scanner remediation");
                pdf.Paragraph(SourceRedactor.Redact(advice), 8.5, indent: 8);
            }
            foreach (var section in a.Sections!)
            {
                pdf.Label(section.Title);
                switch (section.Style)
                {
                    case ActivitySectionStyle.Diff:
                        pdf.CodeBlock(section.Text, diff: true);
                        break;
                    case ActivitySectionStyle.Code:
                        pdf.CodeBlock(section.Text);
                        break;
                    default:
                        pdf.Paragraph(section.Text, 8.5, indent: 8);
                        break;
                }
            }
            pdf.Divider();
        }
    }

    private static string? Refs(SecurityFinding f)
    {
        var refs = f.CweIds.Concat(f.AdvisoryIds).ToArray();
        return refs.Length == 0 ? f.RuleId : f.RuleId + " · " + string.Join(", ", refs.Take(4));
    }

    public static string Label(SessionActivityKind kind) => kind switch
    {
        SessionActivityKind.Scan => "Scan",
        SessionActivityKind.Verdict => "Verdict",
        SessionActivityKind.AiAnalysis => "AI analysis",
        SessionActivityKind.FixProposed => "Fix proposal",
        SessionActivityKind.FixApplied => "Fix applied",
        SessionActivityKind.FixUndone => "Fix undone",
        SessionActivityKind.ReportExported => "Export",
        _ => kind.ToString(),
    };

    private static PdfColor KindColor(SessionActivityKind kind) => kind switch
    {
        SessionActivityKind.FixApplied => PdfColor.FromHex("#15803D"),
        SessionActivityKind.FixUndone => SeverityColor(Severity.High),
        SessionActivityKind.Scan => Band,
        _ => PdfColor.Black,
    };

    private string Local(DateTimeOffset value, string format = "yyyy-MM-dd HH:mm:ss") =>
        TimeZoneInfo.ConvertTime(value, _zone).ToString(format, CultureInfo.InvariantCulture);

    private static string Count(int value) => value.ToString("N0", CultureInfo.InvariantCulture);

    private static string Bytes(long bytes) => bytes switch
    {
        >= 1L << 30 => string.Create(CultureInfo.InvariantCulture, $"{bytes / (double)(1L << 30):0.0} GB"),
        >= 1L << 20 => string.Create(CultureInfo.InvariantCulture, $"{bytes / (double)(1L << 20):0.0} MB"),
        >= 1L << 10 => string.Create(CultureInfo.InvariantCulture, $"{bytes / 1024.0:0.0} KB"),
        _ => string.Create(CultureInfo.InvariantCulture, $"{bytes} B"),
    };
}
