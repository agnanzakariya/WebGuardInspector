namespace WebGuard.Core.Scanning;

/// <summary>User-configurable scan behaviour. Immutable; persisted by the settings store.</summary>
public sealed record ScanOptions
{
    public static readonly IReadOnlyList<string> DefaultExcludedDirectories =
    [
        ".git", ".vs", ".idea", "node_modules", "bin", "obj", "dist", "build",
        ".next", ".venv", "venv", "__pycache__", "packages", "TestResults",
    ];

    /// <summary>Holds commented-out copies of fixed files (see Fixing.WreckCopy). Always excluded, whatever the settings say.</summary>
    public const string WreckFolder = "wreck";

    public const long DefaultMaxHashBytes = 100L * 1024 * 1024;
    public static readonly TimeSpan DefaultEngineTimeout = TimeSpan.FromMinutes(10);

    /// <summary>Directory names (not paths) skipped at any depth. Case-insensitive.</summary>
    public IReadOnlyList<string> ExcludedDirectories { get; init; } = DefaultExcludedDirectories;

    /// <summary>Files larger than this are inventoried but not hashed.</summary>
    public long MaxHashBytes { get; init; } = DefaultMaxHashBytes;

    /// <summary>Number of files hashed concurrently. 1 = sequential.</summary>
    public int MaxDegreeOfParallelism { get; init; } = Math.Clamp(Environment.ProcessorCount / 2, 1, 4);

    /// <summary>Never true in v0.2: links are not followed so a scan cannot escape the selected root.</summary>
    public bool FollowReparsePoints { get; init; }

    /// <summary>Upper bound for a single security engine run.</summary>
    public TimeSpan EngineTimeout { get; init; } = DefaultEngineTimeout;

    /// <summary>
    /// Reuse the findings of files that did not change since the previous scan of the same folder (same SHA-256, same
    /// engine version, rules and signatures) instead of sending them to the engines again.
    /// </summary>
    public bool ReuseUnchangedResults { get; init; } = true;

    public static ScanOptions Default { get; } = new();

    public ScanOptions Normalize() => this with
    {
        ExcludedDirectories = ExcludedDirectories
            .Select(d => d.Trim().Trim('\\', '/'))
            .Where(d => d.Length > 0)
            .Append(WreckFolder)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray(),
        MaxHashBytes = Math.Max(1, MaxHashBytes),
        MaxDegreeOfParallelism = Math.Clamp(MaxDegreeOfParallelism, 1, 16),
        FollowReparsePoints = false,
        EngineTimeout = EngineTimeout <= TimeSpan.Zero ? DefaultEngineTimeout : EngineTimeout,
    };
}
