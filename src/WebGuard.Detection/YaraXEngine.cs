using System.Text.Json;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;

namespace WebGuard.Detection;

/// <summary>YARA-X ("yr") signature matching with local rules. Files are only read, never executed.</summary>
public sealed class YaraXEngine(IExternalProcessRunner runner, Func<string, ExternalToolOptions>? options = null, TimeProvider? timeProvider = null)
    : ExternalToolEngine(runner, options, timeProvider)
{
    public const string Id = "yara-x";

    public override SecurityEngineInfo Info { get; } = new(
        Id, "YARA-X", EngineKind.MalwareSignature,
        "Malware signature matching with local rules.",
        "Phase 2", "https://virustotal.github.io/yara-x/");

    protected override IReadOnlyList<string> ExecutableNames => ["yr"];
    protected override string? BundledRulesFolder => "yara";

    protected override async Task<IReadOnlyList<SecurityFinding>> RunAsync(EngineInvocation invocation, CancellationToken cancellationToken)
    {
        List<string> args = ["scan", "--output-format", "ndjson", "--print-meta", "--recursive"];
        args.AddRange(invocation.RulePaths);
        args.Add(invocation.Request.RootFolder);

        var result = await RunToolAsync(invocation, args, cancellationToken).ConfigureAwait(false);
        EnsureComplete(result);
        if (result.ExitCode != 0) throw new EngineRunException("YARA-X failed (" + Describe(result) + ").");
        return Parse(result.StandardOutput, invocation.Request.RootFolder, Time.GetUtcNow());
    }

    /// <summary>
    /// Accepts NDJSON (one object per scanned file: <c>{"path":…,"rules":[{"identifier":…,"meta":…}]}</c>), a stream of
    /// pretty-printed objects, or a single document with a "matches" array, so format changes between yr releases are tolerated.
    /// </summary>
    public static IReadOnlyList<SecurityFinding> Parse(string output, string rootFolder, DateTimeOffset detectedAtUtc)
    {
        var findings = new List<SecurityFinding>();
        var reader = new Utf8JsonReader(System.Text.Encoding.UTF8.GetBytes(output ?? string.Empty),
            new JsonReaderOptions { AllowMultipleValues = true });
        while (reader.Read())
        {
            using var document = JsonDocument.ParseValue(ref reader);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) continue;
            var entries = root.Child("matches").ValueKind == JsonValueKind.Array ? root.Items("matches") : [root];
            foreach (var entry in entries)
            {
                var file = entry.GetString("path") ?? entry.GetString("file");
                if (file is null) continue;
                var rules = entry.Child("rules").ValueKind == JsonValueKind.Array
                    ? entry.Items("rules")
                    : entry.GetString("rule") is not null || entry.GetString("identifier") is not null ? [entry] : [];
                foreach (var rule in rules) findings.Add(ToFinding(rule, file, rootFolder, detectedAtUtc));
            }
        }
        return findings;
    }

    private static SecurityFinding ToFinding(JsonElement rule, string file, string rootFolder, DateTimeOffset detectedAtUtc)
    {
        var identifier = rule.GetString("identifier") ?? rule.GetString("rule") ?? rule.GetString("name") ?? "yara.unknown";
        var ns = rule.GetString("namespace");
        var ruleId = string.IsNullOrEmpty(ns) || ns == "default" ? identifier : $"{ns}.{identifier}";
        var meta = ReadMeta(rule.Child("meta"));
        var category = meta.TryGetValue("category", out var c) && c.Equals("malware", StringComparison.OrdinalIgnoreCase)
            ? FindingCategory.Malware
            : FindingCategory.SuspiciousPattern;
        var path = EngineOutput.ToRelative(rootFolder, file);
        var description = meta.GetValueOrDefault("description") ?? $"YARA rule '{identifier}' matched this file.";

        return EngineOutput.Create(
            Id, ruleId,
            meta.GetValueOrDefault("title") ?? "Signature match: " + identifier,
            description,
            category,
            EngineOutput.FromLabel(meta.GetValueOrDefault("severity"), category == FindingCategory.Malware ? Severity.Critical : Severity.High),
            EngineOutput.ConfidenceFromLabel(meta.GetValueOrDefault("confidence"), Confidence.Medium),
            new SourceLocation(path, 0, 0),
            null,
            [new Evidence("signature", "Matched rule", ruleId, "yara-x")],
            [],
            [],
            meta.GetValueOrDefault("remediation") ?? "Inspect the file before running or deploying it. Do not execute it on this machine.",
            detectedAtUtc);
    }

    /// <summary>Meta is emitted as an object or as an array of [key, value] pairs depending on the yr version.</summary>
    private static Dictionary<string, string> ReadMeta(JsonElement meta)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (meta.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in meta.EnumerateObject())
                result[p.Name] = p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString()! : p.Value.GetRawText();
        }
        else if (meta.ValueKind == JsonValueKind.Array)
        {
            foreach (var pair in meta.EnumerateArray())
            {
                if (pair.ValueKind != JsonValueKind.Array || pair.GetArrayLength() != 2) continue;
                var value = pair[1];
                result[pair[0].GetString() ?? string.Empty] = value.ValueKind == JsonValueKind.String ? value.GetString()! : value.GetRawText();
            }
        }
        return result;
    }
}
