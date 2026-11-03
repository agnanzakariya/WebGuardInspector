using System.Text.Json.Serialization;

namespace WebGuard.Core.Findings;

[JsonConverter(typeof(JsonStringEnumConverter<Severity>))]
public enum Severity { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }

[JsonConverter(typeof(JsonStringEnumConverter<Confidence>))]
public enum Confidence { Low, Medium, High }

/// <summary>Lifecycle: Detect → Correlate → Analyze → Validate → Remember → Reuse.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<ValidationStatus>))]
public enum ValidationStatus { New, NeedsReview, Confirmed, FalsePositive, AcceptedRisk, Fixed }

/// <summary>Distinguishes deterministic engine output from AI hypotheses (AI may never be the sole basis for a verdict).</summary>
[JsonConverter(typeof(JsonStringEnumConverter<FindingOrigin>))]
public enum FindingOrigin { Engine, AiHypothesis, Manual }

[JsonConverter(typeof(JsonStringEnumConverter<FindingCategory>))]
public enum FindingCategory { Vulnerability, Secret, VulnerableDependency, Malware, SuspiciousPattern, Configuration }

public sealed record SourceLocation(string RelativePath, int StartLine, int EndLine, int? StartColumn = null, int? EndColumn = null)
{
    public override string ToString() => StartLine > 0 ? $"{RelativePath}:{StartLine}" : RelativePath;
}

/// <summary>Evidence supporting a finding. Snippets must already be redacted before they reach this type.</summary>
public sealed record Evidence(string Kind, string Summary, string? RedactedSnippet, string Source);

public sealed record SecurityFinding(
    Guid Id,
    string Fingerprint,
    string EngineId,
    string RuleId,
    string Title,
    string Description,
    FindingCategory Category,
    Severity Severity,
    Confidence Confidence,
    FindingOrigin Origin,
    SourceLocation Location,
    IReadOnlyList<Evidence> Evidence,
    IReadOnlyList<string> CweIds,
    IReadOnlyList<string> AdvisoryIds,
    string? Remediation,
    ValidationStatus Status,
    DateTimeOffset DetectedAtUtc);

/// <summary>Counts per severity, used by the dashboard.</summary>
public sealed record SeveritySummary(int Critical, int High, int Medium, int Low, int Info)
{
    public static SeveritySummary Empty { get; } = new(0, 0, 0, 0, 0);

    public int Total => Critical + High + Medium + Low + Info;

    public static SeveritySummary From(IEnumerable<SecurityFinding> findings)
    {
        int c = 0, h = 0, m = 0, l = 0, i = 0;
        foreach (var f in findings)
        {
            switch (f.Severity)
            {
                case Severity.Critical: c++; break;
                case Severity.High: h++; break;
                case Severity.Medium: m++; break;
                case Severity.Low: l++; break;
                default: i++; break;
            }
        }
        return new SeveritySummary(c, h, m, l, i);
    }
}
