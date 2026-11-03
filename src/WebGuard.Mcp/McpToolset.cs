using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using WebGuard.AI;
using WebGuard.Core.AI;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Intelligence;
using WebGuard.Core.Knowledge;
using WebGuard.Core.Scanning;
using WebGuard.Presentation.Services;
using WebGuard.Scanner;

namespace WebGuard.Mcp;

/// <summary>Everything the tools need, injected so tests can substitute fakes.</summary>
public sealed record McpServices(
    Func<AppSettings> Settings,
    Func<IReadOnlyList<ISecurityEngine>> RuleEngines,
    IReadOnlyList<IFindingEnricher> Enrichers,
    IVulnerabilityIntelligence Vulnerabilities,
    IReadOnlyList<IMalwareHashIntelligence> MalwareSources,
    IAiSecurityAnalyst Analyst,
    ISecondBrainRepository SecondBrain);

/// <summary>Raised by a tool for a user-facing error (bad argument, path outside the project, …).</summary>
public sealed class McpToolException(string message) : Exception(message);

/// <summary>
/// The tools from <see cref="McpToolCatalog"/> that are implemented, scoped to one project folder.
/// Read-only tools are always listed. Tools that run engines or send data off the machine are listed only when the
/// person configuring the server approved them with <c>--allow</c>; their annotations also let MCP clients ask per call.
/// Second Brain tools work once a vault is configured in WebGuard's Settings.
/// </summary>
public sealed class McpToolset
{
    public const int MaxListedFiles = 2000;
    public const int MaxManifestChars = 100_000;

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    private static readonly HashSet<string> ManifestNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
        "requirements.txt", "requirements-dev.txt", "Pipfile", "Pipfile.lock", "poetry.lock", "pyproject.toml", "uv.lock",
        "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
        "packages.lock.json", "packages.config", "Directory.Packages.props", "composer.json", "composer.lock",
        "Gemfile", "Gemfile.lock", "mix.lock", "pubspec.yaml", "pubspec.lock",
    };

    private readonly McpServices _services;
    private readonly McpAuditLog _audit;
    private readonly Dictionary<string, Tool> _tools;

    public McpToolset(ProjectScope scope, McpServices services, McpAuditLog audit, IEnumerable<string> approvedTools)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(audit);
        Scope = scope;
        _services = services;
        _audit = audit;
        var approved = new HashSet<string>(approvedTools ?? [], StringComparer.OrdinalIgnoreCase);
        var all = AllTools().ToDictionary(t => t.Descriptor.Name, StringComparer.Ordinal);
        _tools = all;
        Enabled = all.Values
            .Where(t => !t.Descriptor.RequiresHumanApproval || approved.Contains("all") || approved.Contains(t.Descriptor.Name))
            .Select(t => t.Descriptor.Name)
            .ToHashSet(StringComparer.Ordinal);
    }

    public ProjectScope Scope { get; }

    /// <summary>Names of the tools this server instance exposes.</summary>
    public IReadOnlySet<string> Enabled { get; }

    /// <summary>Implemented tools, whether enabled here or not.</summary>
    public IEnumerable<McpToolDescriptor> Implemented => _tools.Values.Select(t => t.Descriptor);

    public bool IsKnown(string name) => _tools.ContainsKey(name);

    public JsonArray Describe() => new([.. _tools.Values.Where(t => Enabled.Contains(t.Descriptor.Name)).Select(t => (JsonNode)new JsonObject
    {
        ["name"] = t.Descriptor.Name,
        ["title"] = t.Title,
        ["description"] = t.Descriptor.Description + (t.Descriptor.RequiresHumanApproval ? " Requires human approval." : string.Empty),
        ["inputSchema"] = t.Schema.DeepClone(),
        ["annotations"] = new JsonObject
        {
            ["title"] = t.Title,
            ["readOnlyHint"] = t.Descriptor.Access == McpToolAccess.ReadOnly,
            ["destructiveHint"] = false,
            ["idempotentHint"] = t.Descriptor.Access == McpToolAccess.ReadOnly,
            ["openWorldHint"] = t.Descriptor.Access == McpToolAccess.NetworkLookup,
        },
    })]);

    public async Task<(string Text, bool IsError)> CallAsync(string name, JsonObject arguments, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var sw = Stopwatch.StartNew();
        if (!_tools.TryGetValue(name, out var tool)) throw new McpToolException("Unknown tool: " + name);
        if (!Enabled.Contains(name))
        {
            var denied = $"Tool '{name}' requires human approval and is not enabled. Start the server with --allow {name} to permit it.";
            _audit.Record(Scope.Root, name, arguments, "denied", sw.Elapsed);
            return (denied, true);
        }

        try
        {
            var text = await tool.Handler(arguments, cancellationToken).ConfigureAwait(false);
            _audit.Record(Scope.Root, name, arguments, "ok", sw.Elapsed);
            return (text, false);
        }
        catch (Exception ex) when (ex is McpToolException or InvalidOperationException or HttpRequestException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            _audit.Record(Scope.Root, name, arguments, "error", sw.Elapsed, ex.Message);
            return (ex.Message, true);
        }
    }

    private sealed record Tool(McpToolDescriptor Descriptor, string Title, JsonObject Schema, Func<JsonObject, CancellationToken, Task<string>> Handler);

    private IEnumerable<Tool> AllTools()
    {
        McpToolDescriptor D(string name) => McpToolCatalog.Tools.Single(t => t.Name == name);

        yield return new Tool(D("list_project_files"), "List project files",
            Schema(("path", "string", "Sub-folder relative to the project root (default: the root)", false),
                   ("max", "integer", $"Maximum entries to return (default 300, at most {MaxListedFiles})", false)),
            ListProjectFilesAsync);
        yield return new Tool(D("read_source_context"), "Read source context",
            Schema(("path", "string", "File path relative to the project root", true),
                   ("line", "integer", "1-based line to centre on (default 1)", false),
                   ("radius", "integer", "Lines before and after (default 20, at most 80)", false)),
            ReadSourceContextAsync);
        yield return new Tool(D("get_dependency_manifest"), "Get dependency manifest",
            Schema(("path", "string", "Manifest or lockfile to read; omit to list the manifests in the project", false)),
            GetDependencyManifestAsync);
        yield return new Tool(D("run_security_rules"), "Run security engines",
            Schema(("engine", "string", "semgrep, gitleaks, osv-scanner, yara-x or all", true)),
            RunSecurityRulesAsync);
        yield return new Tool(D("lookup_vulnerability"), "Look up package vulnerabilities",
            Schema(("ecosystem", "string", "OSV ecosystem: npm, PyPI, NuGet, Maven, Go, crates.io, RubyGems, Packagist, Pub", true),
                   ("name", "string", "Package name", true),
                   ("version", "string", "Package version", true)),
            LookupVulnerabilityAsync);
        yield return new Tool(D("lookup_malware_hash"), "Look up malware hash",
            Schema(("sha256", "string", "SHA-256 of a file (64 hex characters)", true)),
            LookupMalwareHashAsync);
        yield return new Tool(D("search_similar_findings"), "Search the Second Brain",
            Schema(("query", "string", "What to look for, e.g. 'SQL injection in repositories' or a rule id", true),
                   ("take", "integer", "Maximum results (default 10, at most 25)", false)),
            SearchSimilarFindingsAsync);
        yield return new Tool(D("save_security_finding"), "Save finding to the Second Brain",
            Schema(("path", "string", "File path relative to the project root", true),
                   ("line", "integer", "1-based line (0 when not line-specific)", false),
                   ("title", "string", "Short title of the weakness", true),
                   ("description", "string", "What is wrong and why it matters", true),
                   ("severity", "string", "Critical, High, Medium, Low or Info", true),
                   ("cwe", "string", "Optional CWE id, e.g. CWE-89", false),
                   ("remediation", "string", "Optional suggested fix", false)),
            SaveSecurityFindingAsync);
        yield return new Tool(D("propose_remediation"), "Propose remediation",
            Schema(("path", "string", "File path relative to the project root", true),
                   ("line", "integer", "1-based line of the issue", true),
                   ("issue", "string", "Short description of the suspected weakness", true)),
            ProposeRemediationAsync);
    }

    private Task<string> ListProjectFilesAsync(JsonObject args, CancellationToken cancellationToken)
    {
        var start = Resolve(OptionalString(args, "path") ?? ".");
        if (!Directory.Exists(start)) throw new McpToolException("Not a folder inside the project: " + OptionalString(args, "path"));
        var max = Math.Clamp(OptionalInt(args, "max") ?? 300, 1, MaxListedFiles);
        var files = EnumerateFiles(start, cancellationToken).Take(max + 1).ToList();
        return Task.FromResult(Serialize(new
        {
            root = Scope.Root,
            files = files.Take(max).Select(f => new { path = Scope.ToRelative(f.FullName), bytes = f.Length }),
            truncated = files.Count > max,
            note = "Excluded folders (Settings) and symbolic links/junctions are skipped.",
        }));
    }

    private Task<string> ReadSourceContextAsync(JsonObject args, CancellationToken cancellationToken)
    {
        var path = RequiredString(args, "path");
        Resolve(path);
        var line = Math.Max(1, OptionalInt(args, "line") ?? 1);
        var radius = Math.Clamp(OptionalInt(args, "radius") ?? 20, 0, 80);
        return Task.FromResult(FindingContextBuilder.Excerpt(Scope, path, line, line, radius));
    }

    private Task<string> GetDependencyManifestAsync(JsonObject args, CancellationToken cancellationToken)
    {
        var path = OptionalString(args, "path");
        if (path is null)
        {
            var manifests = EnumerateFiles(Scope.Root, cancellationToken)
                .Where(f => ManifestNames.Contains(f.Name) || f.Extension.Equals(".csproj", StringComparison.OrdinalIgnoreCase))
                .Take(500)
                .Select(f => Scope.ToRelative(f.FullName));
            return Task.FromResult(Serialize(new { manifests }));
        }

        var full = Resolve(path);
        var name = Path.GetFileName(full);
        if (!ManifestNames.Contains(name) && !name.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase))
            throw new McpToolException("Only dependency manifests and lockfiles can be read with this tool; use read_source_context for code.");
        if (!File.Exists(full)) throw new McpToolException("File not found: " + path);
        var text = File.ReadAllText(full);
        var truncated = text.Length > MaxManifestChars;
        return Task.FromResult(SourceRedactor.Redact(truncated ? text[..MaxManifestChars] : text, full) + (truncated ? "\n(… truncated)" : string.Empty));
    }

    private async Task<string> RunSecurityRulesAsync(JsonObject args, CancellationToken cancellationToken)
    {
        var engine = RequiredString(args, "engine").Trim().ToLowerInvariant();
        var engines = _services.RuleEngines().Where(e => engine == "all" || e.Info.Id == engine).ToArray();
        if (engines.Length == 0)
            throw new McpToolException($"Unknown engine '{engine}'. Use one of: {string.Join(", ", _services.RuleEngines().Select(e => e.Info.Id))}, all.");

        var report = await new LocalFolderScanner(engines, _services.Enrichers)
            .ScanAsync(Scope.Root, _services.Settings().ToScanOptions(), null, cancellationToken).ConfigureAwait(false);
        return Serialize(new
        {
            files = report.Statistics.FileCount,
            engines = report.Engines.Select(e => new { e.EngineId, e.Outcome, e.Version, e.FindingCount, e.Message }),
            findingCount = report.Findings.Count,
            findings = report.Findings.Take(50).Select(f => new
            {
                severity = f.Severity.ToString(),
                f.EngineId,
                f.RuleId,
                f.Title,
                location = f.Location.ToString(),
                references = f.CweIds.Concat(f.AdvisoryIds),
                evidence = f.Evidence.Select(e => SourceRedactor.Redact(e.RedactedSnippet)),
                f.Remediation,
            }),
            truncated = report.Findings.Count > 50,
        });
    }

    private async Task<string> LookupVulnerabilityAsync(JsonObject args, CancellationToken cancellationToken)
    {
        var package = new PackageCoordinate(RequiredString(args, "ecosystem"), RequiredString(args, "name"), RequiredString(args, "version"));
        var records = await _services.Vulnerabilities.LookupAsync(package, cancellationToken).ConfigureAwait(false);
        return Serialize(new
        {
            package = $"{package.Ecosystem}/{package.Name}@{package.Version}",
            vulnerabilities = records.Select(r => new
            {
                r.Id,
                r.Aliases,
                r.Summary,
                severity = r.Severity.ToString(),
                r.FixedVersions,
                r.KnownExploited,
                source = r.SourceId,
            }),
        });
    }

    private async Task<string> LookupMalwareHashAsync(JsonObject args, CancellationToken cancellationToken)
    {
        var sha256 = RequiredString(args, "sha256");
        var results = new List<object>();
        foreach (var source in _services.MalwareSources)
        {
            var status = await source.GetStatusAsync(cancellationToken).ConfigureAwait(false);
            if (status.Availability != EngineAvailability.Ready)
            {
                results.Add(new { source = source.Source.DisplayName, available = false, status.Message });
                continue;
            }
            var verdict = await source.LookupAsync(sha256, cancellationToken).ConfigureAwait(false);
            results.Add(new { source = source.Source.DisplayName, available = true, knownMalicious = verdict?.IsKnownMalicious, family = verdict?.Family });
        }
        return Serialize(new { sha256 = sha256.ToLowerInvariant(), results });
    }

    private async Task<string> ProposeRemediationAsync(JsonObject args, CancellationToken cancellationToken)
    {
        var path = RequiredString(args, "path");
        Resolve(path);
        var line = Math.Max(1, OptionalInt(args, "line") ?? 1);
        var issue = RequiredString(args, "issue");
        var status = await _services.Analyst.GetStatusAsync(cancellationToken).ConfigureAwait(false);
        if (status.Availability != EngineAvailability.Ready)
            throw new McpToolException("The local AI analyst is not available: " + status.Message);

        var location = new SourceLocation(path, line, line);
        var finding = new SecurityFinding(Guid.NewGuid(), FindingFingerprint.Compute("mcp-client", "reported-issue", path, issue), "mcp-client",
            "reported-issue", issue, issue, FindingCategory.SuspiciousPattern, Severity.Medium, Confidence.Low, FindingOrigin.Manual,
            location, [], [], [], null, ValidationStatus.NeedsReview, DateTimeOffset.UtcNow);
        var analysis = await _services.Analyst.AnalyzeAsync(FindingContextBuilder.Build(Scope, finding, []), cancellationToken).ConfigureAwait(false);
        return Serialize(new
        {
            status = "AI hypothesis — not verified. A person must review it; nothing was changed.",
            analysis.Model,
            analysis.Summary,
            analysis.WhyRisky,
            analysis.ProposedRemediation,
            confidence = analysis.Confidence.ToString(),
        });
    }

    private async Task<string> SearchSimilarFindingsAsync(JsonObject args, CancellationToken cancellationToken)
    {
        await RequireSecondBrainAsync(cancellationToken).ConfigureAwait(false);
        var hits = await _services.SecondBrain.SearchSimilarAsync(RequiredString(args, "query"), Math.Clamp(OptionalInt(args, "take") ?? 10, 1, 25), cancellationToken)
            .ConfigureAwait(false);
        return Serialize(new
        {
            results = hits.Select(h => new
            {
                h.Title,
                severity = h.Severity.ToString(),
                status = h.Status.ToString(),
                h.IsVerified,
                h.Project,
                score = h.Similarity,
                note = h.NotePath,
                h.Snippet,
            }),
        });
    }

    /// <summary>Records a finding reported by the MCP client as an unverified hypothesis (status NeedsReview) for a person to validate.</summary>
    private async Task<string> SaveSecurityFindingAsync(JsonObject args, CancellationToken cancellationToken)
    {
        await RequireSecondBrainAsync(cancellationToken).ConfigureAwait(false);
        var path = RequiredString(args, "path");
        Resolve(path);
        var line = Math.Max(0, OptionalInt(args, "line") ?? 0);
        var title = SourceRedactor.Redact(RequiredString(args, "title"));
        if (!Enum.TryParse<Severity>(RequiredString(args, "severity"), ignoreCase: true, out var severity))
            throw new McpToolException("Severity must be Critical, High, Medium, Low or Info.");
        var cwe = OptionalString(args, "cwe") is { } c ? new[] { c.Trim().ToUpperInvariant() } : [];
        var finding = new SecurityFinding(Guid.NewGuid(), FindingFingerprint.Compute("mcp-client", title, path, line.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            "mcp-client", "reported-issue", title, SourceRedactor.Redact(RequiredString(args, "description")), FindingCategory.SuspiciousPattern, severity,
            Confidence.Low, FindingOrigin.AiHypothesis, new SourceLocation(path, line, line), [], cwe, [],
            OptionalString(args, "remediation") is { } fix ? SourceRedactor.Redact(fix) : null, ValidationStatus.NeedsReview, DateTimeOffset.UtcNow);
        await _services.SecondBrain.SaveFindingAsync(finding, Path.GetFileName(Scope.Root), cancellationToken).ConfigureAwait(false);
        return Serialize(new
        {
            saved = true,
            status = "NeedsReview — recorded as an AI hypothesis; a person must validate it in WebGuard or Obsidian.",
            fingerprint = finding.Fingerprint,
        });
    }

    private async Task RequireSecondBrainAsync(CancellationToken cancellationToken)
    {
        var status = await _services.SecondBrain.GetStatusAsync(cancellationToken).ConfigureAwait(false);
        if (status.Availability != EngineAvailability.Ready) throw new McpToolException("Second Brain not available: " + status.Message);
    }

    private string Resolve(string path) =>
        Scope.TryResolve(path, out var full, out var error) ? full : throw new McpToolException(error);

    /// <summary>Files below <paramref name="start"/>, skipping excluded folder names and links, like the scanner.</summary>
    private IEnumerable<FileInfo> EnumerateFiles(string start, CancellationToken cancellationToken)
    {
        var excluded = new HashSet<string>(_services.Settings().ToScanOptions().ExcludedDirectories, StringComparer.OrdinalIgnoreCase);
        var pending = new Stack<DirectoryInfo>();
        pending.Push(new DirectoryInfo(start));
        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = pending.Pop();
            FileSystemInfo[] entries;
            try
            {
                entries = current.GetFileSystemInfos().OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase).ToArray();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }
            foreach (var entry in entries.OfType<DirectoryInfo>().Reverse())
            {
                if (!excluded.Contains(entry.Name) && !entry.Attributes.HasFlag(FileAttributes.ReparsePoint)) pending.Push(entry);
            }
            foreach (var file in entries.OfType<FileInfo>())
            {
                if (!file.Attributes.HasFlag(FileAttributes.ReparsePoint)) yield return file;
            }
        }
    }

    private static string Serialize(object value) => JsonSerializer.Serialize(value, Json);

    private static JsonObject Schema(params (string Name, string Type, string Description, bool Required)[] properties) => new()
    {
        ["type"] = "object",
        ["properties"] = new JsonObject(properties.Select(p => KeyValuePair.Create(p.Name,
            (JsonNode?)new JsonObject { ["type"] = p.Type, ["description"] = p.Description }))),
        ["required"] = new JsonArray([.. properties.Where(p => p.Required).Select(p => (JsonNode)p.Name)]),
        ["additionalProperties"] = false,
    };

    private static string RequiredString(JsonObject args, string name) =>
        OptionalString(args, name) is { Length: > 0 } value ? value : throw new McpToolException($"Argument '{name}' is required.");

    private static string? OptionalString(JsonObject args, string name) =>
        args[name] is JsonValue v && v.TryGetValue<string>(out var s) && !string.IsNullOrWhiteSpace(s) ? s : null;

    private static int? OptionalInt(JsonObject args, string name) => args[name] switch
    {
        JsonValue v when v.TryGetValue<int>(out var i) => i,
        JsonValue v when v.TryGetValue<double>(out var d) => (int)d,
        JsonValue v when v.TryGetValue<string>(out var s) && int.TryParse(s, out var p) => p,
        _ => null,
    };
}
