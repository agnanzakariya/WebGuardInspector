using System.Text.Json;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;

namespace WebGuard.Detection;

/// <summary>Gitleaks directory scan. Secrets are redacted by Gitleaks (--redact) and again before they are stored.</summary>
public sealed class GitleaksEngine(IExternalProcessRunner runner, Func<string, ExternalToolOptions>? options = null, TimeProvider? timeProvider = null)
    : ExternalToolEngine(runner, options, timeProvider)
{
    public const string Id = "gitleaks";

    public override SecurityEngineInfo Info { get; } = new(
        Id, "Gitleaks", EngineKind.SecretDetection,
        "Hardcoded secret detection (gitleaks dir --redact).",
        "Phase 2", "https://github.com/gitleaks/gitleaks");

    protected override IReadOnlyList<string> ExecutableNames => ["gitleaks"];
    protected override IReadOnlyList<string> VersionArguments => ["version"];

    protected override async Task<IReadOnlyList<SecurityFinding>> RunAsync(EngineInvocation invocation, CancellationToken cancellationToken)
    {
        var reportPath = Path.Combine(invocation.Request.WorkingDirectory, "gitleaks.json");
        var root = invocation.Request.RootFolder;
        // "gitleaks dir" exists since 8.19; older releases need "detect --no-git --source".
        var modern = UsesDirCommand(invocation.Version);
        List<string> args = modern ? ["dir", root] : ["detect", "--no-git", "--source", root];
        // Partial redaction (modern releases) keeps the first ~20% of the secret so findings can be triaged;
        // full "--redact" would reduce the evidence to the word REDACTED.
        args.AddRange(["--report-format", "json", "--report-path", reportPath, modern ? "--redact=80" : "--redact",
            "--no-banner", "--exit-code", "0", "--log-level", "error"]);
        foreach (var config in invocation.RulePaths.Where(File.Exists).Take(1)) args.AddRange(["--config", config]);

        try
        {
            var result = await RunToolAsync(invocation, args, cancellationToken).ConfigureAwait(false);
            EnsureComplete(result);
            if (result.ExitCode != 0 || !File.Exists(reportPath))
                throw new EngineRunException("Gitleaks failed (" + Describe(result) + ").");
            var json = await File.ReadAllTextAsync(reportPath, cancellationToken).ConfigureAwait(false);
            return Parse(json, root, Time.GetUtcNow());
        }
        finally
        {
            // The report is already redacted, but nothing secret-adjacent is left behind on disk.
            try { File.Delete(reportPath); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    public static bool UsesDirCommand(string? version) =>
        !Version.TryParse(version, out var v) || v >= new Version(8, 19);

    public static IReadOnlyList<SecurityFinding> Parse(string json, string rootFolder, DateTimeOffset detectedAtUtc)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Array) return [];

        var findings = new List<SecurityFinding>();
        foreach (var leak in document.RootElement.EnumerateArray())
        {
            var ruleId = leak.GetString("RuleID") ?? "gitleaks.unknown";
            var description = leak.GetString("Description") ?? ruleId;
            var path = EngineOutput.ToRelative(rootFolder, leak.GetString("File"));
            var startLine = leak.GetInt("StartLine");
            var location = new SourceLocation(path, startLine, Math.Max(startLine, leak.GetInt("EndLine")),
                leak.GetInt("StartColumn"), leak.GetInt("EndColumn"));
            var match = RedactMatch(leak.GetString("Match"), leak.GetString("Secret"));
            var entropy = leak.GetString("Entropy");

            findings.Add(EngineOutput.Create(
                Id, ruleId,
                "Hardcoded secret: " + ruleId,
                description.TrimEnd('.') + "." +
                (entropy is null ? string.Empty : $" Entropy {entropy}.") +
                " Treat the value as exposed until proven otherwise.",
                FindingCategory.Secret,
                Severity.High,
                Confidence.Medium,
                location,
                // Fingerprint on the redacted match: stable across scans without ever hashing the raw secret.
                match,
                match is null ? [] : [new Evidence("secret", "Redacted match", match, "gitleaks")],
                ["CWE-798"],
                [],
                "Remove the secret from source, rotate/revoke it at the provider, and load it from a secret store or environment variable.",
                detectedAtUtc));
        }
        return findings;
    }

    /// <summary>
    /// Defence in depth: if a raw secret is still present in the match (Gitleaks ran without redaction), mask it.
    /// Gitleaks marks redacted values as "REDACTED" (full) or "&lt;prefix&gt;..." (partial).
    /// </summary>
    private static string? RedactMatch(string? match, string? secret)
    {
        if (string.IsNullOrEmpty(match)) return null;
        var alreadyRedacted = string.IsNullOrEmpty(secret) || secret.Equals("REDACTED", StringComparison.Ordinal) ||
                              secret.EndsWith("...", StringComparison.Ordinal);
        if (!alreadyRedacted && match.Contains(secret!, StringComparison.Ordinal))
            match = match.Replace(secret!, SecretRedactor.Redact(secret), StringComparison.Ordinal);
        return EngineOutput.Snippet(match);
    }
}
