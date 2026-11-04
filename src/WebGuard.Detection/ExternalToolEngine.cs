using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;

namespace WebGuard.Detection;

/// <summary>Raised by an adapter when the tool ran but its result cannot be used (bad exit code, unparsable output).</summary>
public sealed class EngineRunException(string message) : Exception(message);

/// <summary>Resolved inputs for one engine run. Adapters add non-fatal problems to <see cref="Warnings"/>.</summary>
public sealed record EngineInvocation(string ExecutablePath, string? Version, IReadOnlyList<string> RulePaths, EngineScanRequest Request)
{
    public List<string> Warnings { get; } = [];
}

/// <summary>
/// Shared plumbing for CLI engines: executable resolution (absolute path only), version probe, rule discovery,
/// timing and error mapping. Adapters only build arguments and parse output.
/// </summary>
public abstract partial class ExternalToolEngine : ISecurityEngine, IIncrementalSecurityEngine
{
    protected const long DefaultMaxOutputBytes = 64L * 1024 * 1024;
    private static readonly TimeSpan VersionTimeout = TimeSpan.FromSeconds(30);

    private readonly Func<string, ExternalToolOptions> _options;

    protected ExternalToolEngine(IExternalProcessRunner runner, Func<string, ExternalToolOptions>? options, TimeProvider? timeProvider)
    {
        ArgumentNullException.ThrowIfNull(runner);
        Runner = runner;
        _options = options ?? ExternalToolOptions.Default;
        Time = timeProvider ?? TimeProvider.System;
    }

    public abstract SecurityEngineInfo Info { get; }

    protected IExternalProcessRunner Runner { get; }
    protected TimeProvider Time { get; }

    /// <summary>File names (without .exe) searched when no explicit path is configured.</summary>
    protected abstract IReadOnlyList<string> ExecutableNames { get; }

    /// <summary>Folder under <c>&lt;app&gt;\rules\</c> holding bundled rules, or null when the tool brings its own.</summary>
    protected virtual string? BundledRulesFolder => null;

    protected virtual IReadOnlyList<string> VersionArguments => ["--version"];

    protected virtual string InstallHint => $"Install {Info.DisplayName} or set its executable path in Settings.";

    /// <summary>Something besides the executable the engine needs (e.g. a signature database); null when all is there.</summary>
    protected virtual string? MissingPrerequisite() => null;

    /// <summary>Status text when the engine is ready; the executable path by default.</summary>
    protected virtual string ReadyMessage(string executablePath) => executablePath;

    /// <summary>Per-file tools scan a temporary folder holding only the changed files; override for other behaviour.</summary>
    public virtual IncrementalScanMode IncrementalMode => IncrementalScanMode.ChangedFilesFolder;

    /// <summary>Extra configuration that decides the result besides version and rules (e.g. a signature database).</summary>
    protected virtual IEnumerable<string> AdditionalStampFiles() => [];

    public string? ConfigurationStamp(EngineStatus status)
    {
        ArgumentNullException.ThrowIfNull(status);
        if (status.Availability != EngineAvailability.Ready || status.ExecutablePath is null) return null;
        try
        {
            var material = new StringBuilder()
                .Append(Info.Id).Append('|').Append(status.Version).Append('|').Append(status.ExecutablePath).Append('|')
                .Append(FileStamp(status.ExecutablePath));
            foreach (var rule in ResolveRules(_options(Info.Id)).Concat(AdditionalStampFiles()).Order(StringComparer.OrdinalIgnoreCase))
            {
                var files = Directory.Exists(rule)
                    ? Directory.EnumerateFiles(rule, "*", SearchOption.AllDirectories).Order(StringComparer.OrdinalIgnoreCase)
                    : (IEnumerable<string>)[rule];
                foreach (var file in files) material.Append('\n').Append(file).Append('|').Append(FileStamp(file));
            }
            return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(material.ToString())));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static string FileStamp(string path)
    {
        var info = new FileInfo(path);
        return info.Exists
            ? string.Create(CultureInfo.InvariantCulture, $"{info.Length}:{info.LastWriteTimeUtc.Ticks}")
            : "missing";
    }

    public async Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        var options = _options(Info.Id);
        if (!options.Enabled)
            return new EngineStatus(EngineAvailability.Disabled, null, null, options.DisabledReason ?? "Disabled in Settings.");

        var (path, error) = ResolveExecutable(options);
        if (path is null)
            return new EngineStatus(error is null ? EngineAvailability.NotInstalled : EngineAvailability.Error, null, null, error ?? InstallHint);

        if (BundledRulesFolder is not null && ResolveRules(options).Length == 0)
            return new EngineStatus(EngineAvailability.Error, null, path, "No rule files found. Configure a rules folder in settings.json.");

        try
        {
            var version = await ProbeVersionAsync(path, cancellationToken).ConfigureAwait(false);
            if (MissingPrerequisite() is { } missing) return new EngineStatus(EngineAvailability.Error, version, path, missing);
            return new EngineStatus(EngineAvailability.Ready, version, path, ReadyMessage(path));
        }
        catch (Exception ex) when (ex is EngineRunException or IOException or System.ComponentModel.Win32Exception)
        {
            return new EngineStatus(EngineAvailability.Error, null, path, ex.Message);
        }
    }

    public async Task<EngineScanResult> ScanAsync(EngineScanRequest request, IProgress<EngineProgress>? progress, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var sw = Stopwatch.StartNew();
        var options = _options(Info.Id);
        var (path, error) = options.Enabled ? ResolveExecutable(options) : (null, options.DisabledReason ?? "Disabled in Settings.");
        if (path is null) return Failed(error ?? InstallHint, sw.Elapsed);

        try
        {
            if (MissingPrerequisite() is { } missing) return Failed(missing, sw.Elapsed);
            progress?.Report(new EngineProgress(Info.Id, $"Running {Info.DisplayName}…", null));
            var version = await ProbeVersionAsync(path, cancellationToken).ConfigureAwait(false);
            var invocation = new EngineInvocation(path, version, ResolveRules(options), request);
            var findings = await RunAsync(invocation, cancellationToken).ConfigureAwait(false);
            return new EngineScanResult(Info.Id, true, findings, sw.Elapsed, null,
                invocation.Warnings.Count == 0 ? null : string.Join(" ", invocation.Warnings));
        }
        catch (Exception ex) when (ex is EngineRunException or IOException or System.ComponentModel.Win32Exception or System.Text.Json.JsonException)
        {
            return Failed(ex.Message, sw.Elapsed);
        }
    }

    /// <summary>Runs the tool and maps its output. Throw <see cref="EngineRunException"/> for tool-level failures.</summary>
    protected abstract Task<IReadOnlyList<SecurityFinding>> RunAsync(EngineInvocation invocation, CancellationToken cancellationToken);

    /// <summary>Extra environment variables for every invocation of the tool (version probe and scan).</summary>
    protected virtual IReadOnlyDictionary<string, string> ToolEnvironment { get; } = new Dictionary<string, string>();

    protected Task<ProcessRunResult> RunToolAsync(
        EngineInvocation invocation,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken) =>
        Runner.RunAsync(new ProcessRunRequest(invocation.ExecutablePath, arguments, invocation.Request.WorkingDirectory,
            invocation.Request.Timeout, DefaultMaxOutputBytes, BuildEnvironment(invocation.ExecutablePath)), cancellationToken);

    /// <summary>
    /// Puts the executable's own folder first on PATH: wrappers such as semgrep.exe launch companion programs
    /// (pysemgrep, semgrep-core) by name, and that folder is often not on PATH for "pip install --user" setups.
    /// </summary>
    private Dictionary<string, string> BuildEnvironment(string executablePath)
    {
        var environment = new Dictionary<string, string>(ToolEnvironment, StringComparer.OrdinalIgnoreCase);
        var directory = Path.GetDirectoryName(executablePath);
        if (!string.IsNullOrEmpty(directory))
            environment["PATH"] = directory + Path.PathSeparator + (Environment.GetEnvironmentVariable("PATH") ?? string.Empty);
        return environment;
    }

    /// <summary>Throws for timeouts and truncated output, which would otherwise yield silently incomplete results.</summary>
    protected void EnsureComplete(ProcessRunResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (result.TimedOut) throw new EngineRunException($"{Info.DisplayName} timed out after {result.Duration.TotalSeconds:0} s.");
        if (result.OutputTruncated) throw new EngineRunException($"{Info.DisplayName} produced more output than the {DefaultMaxOutputBytes / (1024 * 1024)} MB limit.");
    }

    protected static string Describe(ProcessRunResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        // Tools log progress first and the actual error last, so keep the tail.
        var text = (result.StandardError.Length > 0 ? result.StandardError : result.StandardOutput).Trim();
        if (text.Length > 600) text = "…" + text[^600..];
        return $"exit code {result.ExitCode}" + (text.Length > 0 ? ": " + text : string.Empty);
    }

    protected virtual string? ParseVersion(string output)
    {
        var match = VersionPattern().Match(output ?? string.Empty);
        return match.Success ? match.Value : null;
    }

    private async Task<string?> ProbeVersionAsync(string path, CancellationToken cancellationToken)
    {
        var workDir = Path.GetDirectoryName(path) ?? Path.GetTempPath();
        var result = await Runner.RunAsync(new ProcessRunRequest(path, VersionArguments, workDir, VersionTimeout, 64 * 1024,
            BuildEnvironment(path)), cancellationToken).ConfigureAwait(false);
        if (result.TimedOut || result.ExitCode != 0)
            throw new EngineRunException($"Version check failed ({Describe(result)}).");
        return ParseVersion(result.StandardOutput + "\n" + result.StandardError);
    }

    private (string? Path, string? Error) ResolveExecutable(ExternalToolOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.ExecutablePath))
        {
            var configured = options.ExecutablePath.Trim().Trim('"');
            if (!Path.IsPathFullyQualified(configured)) return (null, "Configured executable path must be absolute.");
            if (OperatingSystem.IsWindows() && !configured.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                return (null, "Configured executable must be an .exe file.");
            if (!File.Exists(configured)) return (null, "Configured executable not found: " + configured);
            return (configured, null);
        }
        return (ExecutableLocator.Find(ExecutableNames), null);
    }

    private string[] ResolveRules(ExternalToolOptions options)
    {
        var configured = options.RulePaths
            .Where(p => Path.IsPathFullyQualified(p) && (File.Exists(p) || Directory.Exists(p)))
            .ToArray();
        if (configured.Length > 0 || BundledRulesFolder is null) return configured;

        var bundled = Path.Combine(AppContext.BaseDirectory, "rules", BundledRulesFolder);
        return Directory.Exists(bundled) && Directory.EnumerateFiles(bundled).Any() ? [bundled] : [];
    }

    private EngineScanResult Failed(string error, TimeSpan duration) =>
        new(Info.Id, false, Array.Empty<SecurityFinding>(), duration, null, error);

    [GeneratedRegex(@"\d+\.\d+(\.\d+)?")]
    private static partial Regex VersionPattern();
}
