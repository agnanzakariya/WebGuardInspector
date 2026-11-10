using WebGuard.Core.Findings;
using WebGuard.Core.Scanning;

namespace WebGuard.Presentation.Services;

/// <summary>
/// Records what a person does with a scan (verdicts, AI analyses, fixes, exports) in its Scan History session, including
/// the full result (analysis text, fix explanation, diff, command). Texts are redacted before they are stored. A failure
/// to record never interrupts the work itself.
/// </summary>
public sealed class SessionActivityLog(IScanHistoryStore store, TimeProvider? timeProvider = null)
{
    /// <summary>Longest text kept per section (a diff of a large file is cut with a note).</summary>
    public const int MaxSectionChars = 20_000;

    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    /// <summary>Raised with the scan id after an activity was stored.</summary>
    public event EventHandler<Guid>? Recorded;

    public async Task RecordAsync(ScanReport? report, SessionActivityKind kind, string summary, string? location = null, string? detail = null,
        string? fingerprint = null, IEnumerable<ActivitySection?>? sections = null, string? fileName = null)
    {
        if (report is null) return;
        var kept = sections?
            .Where(s => s is not null && !string.IsNullOrWhiteSpace(s.Text))
            .Select(s => s! with { Text = Cut(SourceRedactor.Redact(s!.Text.TrimEnd(), fileName), MaxSectionChars) })
            .ToArray();
        var activity = new SessionActivity(_time.GetUtcNow(), kind, SourceRedactor.Redact(summary), location,
            string.IsNullOrWhiteSpace(detail) ? null : Cut(SourceRedactor.Redact(detail), 2000), fingerprint,
            kept is { Length: > 0 } ? kept : null);
        try
        {
            await store.AppendActivityAsync(report.ScanId, activity, CancellationToken.None).ConfigureAwait(true);
            Recorded?.Invoke(this, report.ScanId);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            // History is a record of the work, not a precondition for it.
        }
    }

    /// <summary>A section only when there is text, so callers can pass optional parts inline.</summary>
    public static ActivitySection? Section(string title, string? text, ActivitySectionStyle style = ActivitySectionStyle.Text) =>
        string.IsNullOrWhiteSpace(text) ? null : new ActivitySection(title, text, style);

    private static string Cut(string text, int max) => text.Length <= max ? text : text[..max] + $"\n… ({text.Length - max:N0} more characters not kept)";
}
