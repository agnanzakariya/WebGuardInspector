using System.Text.Json;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;

namespace WebGuard.Detection;

/// <summary>Semgrep CE with local rules only: metrics off, no registry, no login.</summary>
public sealed partial class SemgrepEngine(IExternalProcessRunner runner, Func<string, ExternalToolOptions>? options = null, TimeProvider? timeProvider = null)
    : ExternalToolEngine(runner, options, timeProvider)
{
    public const string Id = "semgrep";

    protected override IReadOnlyDictionary<string, string> ToolEnvironment { get; } = new Dictionary<string, string>
    {
        ["SEMGREP_SEND_METRICS"] = "off",
        ["SEMGREP_ENABLE_VERSION_CHECK"] = "0",
        ["PYTHONUTF8"] = "1",
    };

    public override SecurityEngineInfo Info { get; } = new(
        Id, "Semgrep CE", EngineKind.StaticAnalysis,
        "Static analysis with local rules (--metrics=off, no registry).",
        "Phase 2", "https://semgrep.dev");

    protected override IReadOnlyList<string> ExecutableNames => ["semgrep", "pysemgrep"];
    protected override string? BundledRulesFolder => "semgrep";

    private const int MaxUnreadableRetries = 5;

    protected override async Task<IReadOnlyList<SecurityFinding>> RunAsync(EngineInvocation invocation, CancellationToken cancellationToken)
    {
        var root = invocation.Request.RootFolder;
        var skipped = new List<string>();
        ProcessRunResult result;
        while (true)
        {
            // No --quiet: Semgrep's own errors (and crash tracebacks) only appear on stderr otherwise.
            List<string> args = ["scan", "--metrics=off", "--disable-version-check", "--json", "--timeout", "30"];
            foreach (var rules in invocation.RulePaths) args.AddRange(["--config", rules]);
            foreach (var file in skipped) args.AddRange(["--exclude", file]);
            args.Add(root);

            result = await RunToolAsync(invocation, args, cancellationToken).ConfigureAwait(false);
            EnsureComplete(result);
            // Semgrep aborts the whole scan with a PermissionError when a single file cannot be opened (e.g. locked by
            // an antivirus). Exclude that file and run again so the rest of the project is still analysed.
            if (result.ExitCode is (0 or 1) || skipped.Count >= MaxUnreadableRetries) break;
            var unreadable = UnreadableFile(result.StandardError, root);
            if (unreadable is null || skipped.Contains(unreadable, StringComparer.OrdinalIgnoreCase)) break;
            skipped.Add(unreadable);
        }
        if (skipped.Count > 0)
            invocation.Warnings.Add($"Skipped {skipped.Count} unreadable file(s) (locked or access denied): {string.Join(", ", skipped)}.");

        // 0 = clean, 1 = findings (with --error), 2+ = errors. Keep whatever results were produced and report the errors.
        var errors = result.StandardOutput.Length > 0 ? ReadErrors(result.StandardOutput) : null;
        if (errors is null)
            throw new EngineRunException("Semgrep failed (" + Describe(result) + ").");
        var findings = Parse(result.StandardOutput, invocation.Request.RootFolder, Time.GetUtcNow(), invocation.RulePaths);
        if (result.ExitCode is not (0 or 1) && findings.Count == 0)
            throw new EngineRunException($"Semgrep failed (exit code {result.ExitCode}): " + (errors.Count > 0 ? errors[0] : Describe(result)));
        if (errors.Count > 0)
            invocation.Warnings.Add($"Semgrep reported {errors.Count} error(s); results may be incomplete. First: {errors[0]}");
        return findings;
    }

    /// <summary>
    /// Path (relative to the root, '/' separated, as Semgrep's --exclude expects) of the file named in a
    /// "PermissionError: [Errno 13] Permission denied: '…'" traceback, or null when the failure has another cause.
    /// </summary>
    public static string? UnreadableFile(string standardError, string rootFolder)
    {
        var match = PermissionDenied().Match(standardError ?? string.Empty);
        if (!match.Success) return null;
        var reported = match.Groups["path"].Value.Replace(@"\\", @"\", StringComparison.Ordinal);
        var relative = EngineOutput.ToRelative(rootFolder, reported);
        return relative.Length == 0 || relative.StartsWith("..", StringComparison.Ordinal) || Path.IsPathRooted(relative)
            ? null
            : relative.Replace('\\', '/');
    }

    [System.Text.RegularExpressions.GeneratedRegex(@"PermissionError: \[Errno 13\] Permission denied:\s*'(?<path>[^']+)'")]
    private static partial System.Text.RegularExpressions.Regex PermissionDenied();

    /// <summary>Error summaries from Semgrep JSON output, or null when the output is not Semgrep JSON at all.</summary>
    public static IReadOnlyList<string>? ReadErrors(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object) return null;
            return document.RootElement.Items("errors")
                .Select(e =>
                {
                    var message = (e.GetString("message") ?? e.GetString("type") ?? "unknown error").Split('\n')[0].Trim();
                    var path = e.GetString("path");
                    return path is null ? message : $"{message} ({path})";
                })
                .ToArray();
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static IReadOnlyList<SecurityFinding> Parse(string json, string rootFolder, DateTimeOffset detectedAtUtc, IReadOnlyList<string>? rulePaths = null)
    {
        using var document = JsonDocument.Parse(json);
        var prefixes = ConfigPrefixes(rulePaths ?? []);
        var findings = new List<SecurityFinding>();
        foreach (var r in document.RootElement.Items("results"))
        {
            var ruleId = StripConfigPrefix(r.GetString("check_id") ?? "semgrep.unknown", prefixes);
            var extra = r.Child("extra");
            var metadata = extra.Child("metadata");
            var message = extra.GetString("message") ?? ruleId;
            var path = EngineOutput.ToRelative(rootFolder, r.GetString("path"));
            var start = r.Child("start");
            var end = r.Child("end");
            var location = new SourceLocation(path, start.GetInt("line"), Math.Max(start.GetInt("line"), end.GetInt("line")),
                start.GetInt("col"), end.GetInt("col"));
            var lines = extra.GetString("lines");
            // Semgrep prints "requires login" when it cannot show code; never store that as a snippet.
            var snippet = lines is null || lines.Equals("requires login", StringComparison.OrdinalIgnoreCase) ? null : EngineOutput.Snippet(lines);
            var shortRule = ruleId.Split('.')[^1];
            var category = metadata.Strings("category").Any(c => c.Equals("security", StringComparison.OrdinalIgnoreCase)) || metadata.Strings("cwe").Count > 0
                ? FindingCategory.Vulnerability
                : FindingCategory.SuspiciousPattern;

            findings.Add(EngineOutput.Create(
                Id, ruleId,
                Title(shortRule, message),
                message,
                category,
                EngineOutput.FromLabel(extra.GetString("severity"), Severity.Medium),
                EngineOutput.ConfidenceFromLabel(metadata.GetString("confidence"), Confidence.Medium),
                location,
                snippet,
                snippet is null ? [] : [new Evidence("code", "Matched code", SourceRedactor.Redact(snippet, path), "semgrep")],
                EngineOutput.NormalizeCwe(metadata.Strings("cwe")),
                [],
                extra.GetString("fix") is { } fix ? "Suggested fix: " + fix : metadata.GetString("remediation"),
                detectedAtUtc));
        }
        return findings;
    }

    private static string Title(string shortRule, string message)
    {
        // Split on sentence ends only, so "yaml.load …" or "os.system" are not cut at the dot.
        var firstSentence = message.Split(["\n", ". "], 2, StringSplitOptions.None)[0].Trim().TrimEnd('.');
        return firstSentence.Length is > 0 and <= 110 ? firstSentence : shortRule;
    }

    /// <summary>
    /// Semgrep prefixes rules loaded from a local path with that path in dotted form
    /// (C:\app\rules\semgrep → "C.app.rules.semgrep."). Stripping it keeps rule ids, and therefore fingerprints,
    /// identical across machines and install folders.
    /// </summary>
    private static string[] ConfigPrefixes(IEnumerable<string> rulePaths) => rulePaths
        .SelectMany(p => new[] { p, Path.GetDirectoryName(p) ?? string.Empty })
        .Select(p => p.Split(['\\', '/', ':'], StringSplitOptions.RemoveEmptyEntries))
        // Semgrep uses the path relative to its working directory when the rules live below it, so every
        // trailing part of the path ("Rules.semgrep.", "Detection.Rules.semgrep.", …) is a possible prefix.
        .SelectMany(segments => Enumerable.Range(0, segments.Length).Select(i => string.Join('.', segments[i..])))
        .Where(p => p.Length > 0)
        .Select(p => p + ".")
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .OrderByDescending(p => p.Length)
        .ToArray();

    private static string StripConfigPrefix(string ruleId, string[] prefixes)
    {
        foreach (var prefix in prefixes)
        {
            if (ruleId.Length > prefix.Length && ruleId.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return ruleId[prefix.Length..];
        }
        return ruleId;
    }
}
