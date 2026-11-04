using System.Text.Json.Serialization;
using WebGuard.Core.Findings;
using WebGuard.Core.Scanning;

namespace WebGuard.Core.Detection;

[JsonConverter(typeof(JsonStringEnumConverter<EngineKind>))]
public enum EngineKind { StaticAnalysis, SecretDetection, DependencyAudit, MalwareSignature, CodeAnalysis }

[JsonConverter(typeof(JsonStringEnumConverter<EngineAvailability>))]
public enum EngineAvailability { Planned, NotInstalled, Disabled, Ready, Error }

/// <summary>Static description of a security engine.</summary>
public sealed record SecurityEngineInfo(
    string Id,
    string DisplayName,
    EngineKind Kind,
    string Description,
    string PlannedPhase,
    string? HomepageUrl);

/// <summary>Runtime state of an engine on this machine.</summary>
public sealed record EngineStatus(
    EngineAvailability Availability,
    string? Version,
    string? ExecutablePath,
    string Message)
{
    public static EngineStatus Planned(string phase) =>
        new(EngineAvailability.Planned, null, null, $"Interface ready; implementation scheduled for {phase}.");
}

public sealed record EngineScanRequest(
    Guid ScanId,
    string RootFolder,
    IReadOnlyList<FileInventoryItem> Files,
    string WorkingDirectory,
    TimeSpan Timeout);

public sealed record EngineProgress(string EngineId, string Message, double? Percent);

public sealed record EngineScanResult(
    string EngineId,
    bool Succeeded,
    IReadOnlyList<SecurityFinding> Findings,
    TimeSpan Duration,
    string? RawReportPath,
    string? Error);

/// <summary>
/// Adapter around one deterministic detection tool (Semgrep, Gitleaks, OSV-Scanner, YARA-X, Roslyn).
/// Implementations translate tool output into <see cref="SecurityFinding"/> and must never modify source files.
/// </summary>
public interface ISecurityEngine
{
    SecurityEngineInfo Info { get; }

    Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken);

    Task<EngineScanResult> ScanAsync(
        EngineScanRequest request,
        IProgress<EngineProgress>? progress,
        CancellationToken cancellationToken);
}

/// <summary>
/// Configuration for a CLI-based engine. Executables are always invoked by absolute path; when
/// <see cref="ExecutablePath"/> is empty the engine may auto-detect an .exe and reports the resolved absolute path.
/// </summary>
public sealed record ExternalToolOptions(
    string EngineId,
    string? ExecutablePath,
    bool Enabled,
    IReadOnlyList<string> RulePaths,
    string? DisabledReason = null)
{
    public static ExternalToolOptions Default(string engineId) => new(engineId, null, true, []);
}

/// <summary>Allow-listed process execution with timeout, output cap and cancellation.</summary>
public interface IExternalProcessRunner
{
    Task<ProcessRunResult> RunAsync(ProcessRunRequest request, CancellationToken cancellationToken);
}

public sealed record ProcessRunRequest(
    string ExecutablePath,
    IReadOnlyList<string> Arguments,
    string WorkingDirectory,
    TimeSpan Timeout,
    long MaxOutputBytes,
    IReadOnlyDictionary<string, string>? Environment = null,
    string? StandardInput = null);

public sealed record ProcessRunResult(int ExitCode, string StandardOutput, string StandardError, TimeSpan Duration, bool TimedOut, bool OutputTruncated);

/// <summary>How an engine can re-scan only the files that changed since its last run.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<IncrementalScanMode>))]
public enum IncrementalScanMode
{
    /// <summary>Always scans everything (e.g. results depend on an online database that changes daily).</summary>
    None,

    /// <summary>Scans exactly <see cref="EngineScanRequest.Files"/> under the real root folder.</summary>
    ChangedFilesList,

    /// <summary>Scans a whole folder; it is given a temporary copy that holds only the changed files.</summary>
    ChangedFilesFolder,
}

/// <summary>
/// An engine whose result for a file depends only on that file's bytes and the engine's configuration, so the
/// findings of unchanged files can be reused from the previous scan.
/// </summary>
public interface IIncrementalSecurityEngine
{
    IncrementalScanMode IncrementalMode { get; }

    /// <summary>
    /// Identifies everything besides the files that decides the result: version, rules, signature database.
    /// Cached findings are reused only while it is unchanged. Null when it cannot be determined (no reuse).
    /// </summary>
    string? ConfigurationStamp(EngineStatus status);
}
