using System.Text.Json;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;

namespace WebGuard.Detection;

/// <summary>
/// OSV-Scanner over lockfiles/manifests. It queries api.osv.dev with package coordinates (never source code),
/// so the composition root only enables it when external intelligence is allowed.
/// </summary>
public sealed class OsvScannerEngine(IExternalProcessRunner runner, Func<string, ExternalToolOptions>? options = null, TimeProvider? timeProvider = null)
    : ExternalToolEngine(runner, options, timeProvider)
{
    public const string Id = "osv-scanner";

    public override SecurityEngineInfo Info { get; } = new(
        Id, "OSV-Scanner", EngineKind.DependencyAudit,
        "Vulnerable dependency detection from lockfiles (sends package names/versions to OSV.dev).",
        "Phase 2", "https://google.github.io/osv-scanner/");

    protected override IReadOnlyList<string> ExecutableNames => ["osv-scanner", "osv-scanner_windows_amd64"];

    /// <summary>New advisories are published every day, so unchanged lockfiles must still be checked again.</summary>
    public override IncrementalScanMode IncrementalMode => IncrementalScanMode.None;

    protected override async Task<IReadOnlyList<SecurityFinding>> RunAsync(EngineInvocation invocation, CancellationToken cancellationToken)
    {
        var root = invocation.Request.RootFolder;
        // v2 moved source scanning under "scan source"; v1 takes the directory directly.
        List<string> args = IsV2(invocation.Version) ? ["scan", "source"] : [];
        args.AddRange(["--format", "json", "--recursive", root]);

        var result = await RunToolAsync(invocation, args, cancellationToken).ConfigureAwait(false);
        EnsureComplete(result);
        // 0 = no vulnerabilities, 1 = vulnerabilities found, 128 = no package sources found.
        return result.ExitCode switch
        {
            128 => [],
            0 or 1 when result.StandardOutput.Length > 0 => Parse(result.StandardOutput, root, Time.GetUtcNow()),
            _ => throw new EngineRunException("OSV-Scanner failed (" + Describe(result) + ")."),
        };
    }

    public static bool IsV2(string? version) => Version.TryParse(version, out var v) && v.Major >= 2;

    public static IReadOnlyList<SecurityFinding> Parse(string json, string rootFolder, DateTimeOffset detectedAtUtc)
    {
        using var document = JsonDocument.Parse(json);
        var findings = new List<SecurityFinding>();
        foreach (var source in document.RootElement.Items("results"))
        {
            var path = EngineOutput.ToRelative(rootFolder, source.Child("source").GetString("path"));
            foreach (var pkg in source.Items("packages"))
            {
                var package = pkg.Child("package");
                var name = package.GetString("name") ?? "unknown";
                var version = package.GetString("version") ?? "?";
                var ecosystem = package.GetString("ecosystem") ?? "unknown";
                var vulns = pkg.Items("vulnerabilities")
                    .GroupBy(v => v.GetString("id") ?? string.Empty, StringComparer.Ordinal)
                    .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);

                // Groups merge aliases (GHSA + CVE) into one issue; fall back to one finding per vulnerability.
                var groups = pkg.Items("groups").Select(g => (Ids: g.Strings("ids"), Score: g.GetString("max_severity"))).ToList();
                if (groups.Count == 0) groups = vulns.Keys.Select(id => ((IReadOnlyList<string>)[id], (string?)null)).ToList();

                foreach (var (ids, score) in groups)
                {
                    var primary = ids.FirstOrDefault(vulns.ContainsKey) ?? (ids.Count > 0 ? ids[0] : "OSV-UNKNOWN");
                    vulns.TryGetValue(primary, out var vuln);
                    var aliases = ids.Concat(vuln.Strings("aliases")).Distinct(StringComparer.Ordinal).ToArray();
                    var fixedVersions = FixedVersions(vuln, name);
                    var summary = vuln.GetString("summary") ?? vuln.GetString("details")?.Split('\n')[0] ?? primary;
                    var severity = string.IsNullOrEmpty(score)
                        ? EngineOutput.FromLabel(vuln.Child("database_specific").GetString("severity"), Severity.Medium)
                        : EngineOutput.FromCvssScore(score);
                    var coordinate = $"{ecosystem}/{name}@{version}";

                    findings.Add(EngineOutput.Create(
                        Id, primary,
                        $"{name} {version}: {summary}",
                        $"{coordinate} is affected by {string.Join(", ", aliases)}." +
                        (string.IsNullOrEmpty(score) ? string.Empty : $" Max CVSS score {score}."),
                        FindingCategory.VulnerableDependency,
                        severity,
                        Confidence.High,
                        new SourceLocation(path, 0, 0),
                        coordinate,
                        [new Evidence("package", "Affected package", coordinate, "osv-scanner")],
                        EngineOutput.NormalizeCwe(vuln.Child("database_specific").Strings("cwe_ids")),
                        aliases,
                        fixedVersions.Count > 0
                            ? $"Upgrade {name} to {string.Join(" or ", fixedVersions)} or later."
                            : "No fixed version is published yet. Consider an alternative package or mitigating controls.",
                        detectedAtUtc));
                }
            }
        }
        return findings;
    }

    private static List<string> FixedVersions(JsonElement vuln, string packageName) => vuln.Items("affected")
        .Where(a => string.Equals(a.Child("package").GetString("name"), packageName, StringComparison.OrdinalIgnoreCase))
        .SelectMany(a => a.Items("ranges"))
        .SelectMany(r => r.Items("events"))
        .Select(e => e.GetString("fixed"))
        .OfType<string>()
        .Distinct(StringComparer.Ordinal)
        .ToList();
}
