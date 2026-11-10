using System.Text.Json.Serialization;

namespace WebGuard.Core.Scanning;

/// <summary>What happened in a scan session.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<SessionActivityKind>))]
public enum SessionActivityKind
{
    Scan,
    Verdict,
    AiAnalysis,
    FixProposed,
    FixApplied,
    FixUndone,
    ReportExported,
}

/// <summary>How an activity section is shown: prose, a command/code block, or a unified diff.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<ActivitySectionStyle>))]
public enum ActivitySectionStyle { Text, Code, Diff }

/// <summary>A titled part of an activity's full result, e.g. an AI analysis's "Why it matters" or a fix's diff.</summary>
public sealed record ActivitySection(string Title, string Text, ActivitySectionStyle Style = ActivitySectionStyle.Text);

/// <summary>
/// One step of a scan session, shown on the Scan History page and in the PDF report. Texts are already redacted;
/// <paramref name="Location"/> is the finding's or file's relative path (with line), <paramref name="Fingerprint"/> links
/// the activity to its finding, and <paramref name="Sections"/> hold the full result (AI analysis, fix explanation and diff…).
/// </summary>
public sealed record SessionActivity(
    DateTimeOffset AtUtc,
    SessionActivityKind Kind,
    string Summary,
    string? Location = null,
    string? Detail = null,
    string? Fingerprint = null,
    IReadOnlyList<ActivitySection>? Sections = null);

/// <summary>Counts per kind, for the session résumé.</summary>
public sealed record SessionActivitySummary(int Verdicts, int AiAnalyses, int FixesProposed, int FixesApplied, int FixesUndone, int Exports)
{
    public static SessionActivitySummary From(IEnumerable<SessionActivity> activities)
    {
        ArgumentNullException.ThrowIfNull(activities);
        var list = activities.ToList();
        int Count(SessionActivityKind kind) => list.Count(a => a.Kind == kind);
        return new SessionActivitySummary(Count(SessionActivityKind.Verdict), Count(SessionActivityKind.AiAnalysis), Count(SessionActivityKind.FixProposed),
            Count(SessionActivityKind.FixApplied), Count(SessionActivityKind.FixUndone), Count(SessionActivityKind.ReportExported));
    }
}
