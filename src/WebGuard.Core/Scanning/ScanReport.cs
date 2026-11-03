using WebGuard.Core.Findings;

namespace WebGuard.Core.Scanning;

/// <summary>Complete, serializable result of one scan session.</summary>
public sealed record ScanReport(
    string SchemaVersion,
    string ToolVersion,
    Guid ScanId,
    string RootFolder,
    string MachineName,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset FinishedAtUtc,
    ScanOptions Options,
    ScanStatistics Statistics,
    IReadOnlyList<EngineRunSummary> Engines,
    IReadOnlyList<FileInventoryItem> Files,
    IReadOnlyList<SecurityFinding> Findings)
{
    public const string CurrentSchemaVersion = "1.1";

    public TimeSpan Duration => FinishedAtUtc - StartedAtUtc;
}

/// <summary>What each security engine did during a scan: Completed, Failed, NotInstalled, Disabled or Planned.</summary>
public sealed record EngineRunSummary(
    string EngineId,
    string DisplayName,
    string Outcome,
    string? Version,
    int FindingCount,
    string? Message);
