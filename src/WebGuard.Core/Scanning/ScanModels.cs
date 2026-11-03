using System.Text.Json.Serialization;

namespace WebGuard.Core.Scanning;

/// <summary>Result status of a single inventory entry.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<FileScanStatus>))]
public enum FileScanStatus
{
    Hashed,
    SkippedSize,
    SkippedLink,
    Error,
}

/// <summary>Phase reported while a scan is running.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<ScanPhase>))]
public enum ScanPhase
{
    Discovering,
    Hashing,
    Analyzing,
    Completed,
}

/// <summary>A single file (or unreadable directory) discovered under the scan root.</summary>
public sealed record FileInventoryItem(
    string RelativePath,
    string Extension,
    long SizeBytes,
    DateTimeOffset? LastModifiedUtc,
    string? Sha256,
    FileScanStatus Status,
    double HashDurationMs,
    string? Error)
{
    /// <summary>File name without the directory part.</summary>
    [JsonIgnore]
    public string FileName => Path.GetFileName(RelativePath);

    /// <summary>Directory part of the relative path; empty for root-level files.</summary>
    [JsonIgnore]
    public string Directory => Path.GetDirectoryName(RelativePath) ?? string.Empty;
}

/// <summary>
/// Progress snapshot. While hashing, <see cref="Examined"/> and <see cref="Total"/> count files and byte counters drive the
/// percentage; while analyzing they count security engines.
/// </summary>
public sealed record ScanProgress(
    ScanPhase Phase,
    int Examined,
    int Total,
    long BytesProcessed,
    long TotalBytes,
    string CurrentFile)
{
    public double Percent => Phase switch
    {
        ScanPhase.Discovering => 0,
        ScanPhase.Completed => 100,
        ScanPhase.Analyzing => Total > 0 ? Math.Clamp(100.0 * Examined / Total, 0, 100) : 100,
        _ when TotalBytes > 0 => Math.Clamp(100.0 * BytesProcessed / TotalBytes, 0, 100),
        _ when Total > 0 => Math.Clamp(100.0 * Examined / Total, 0, 100),
        _ => 100,
    };
}

/// <summary>Aggregated counters for a finished scan.</summary>
public sealed record ScanStatistics(
    int FileCount,
    int HashedCount,
    int SkippedCount,
    int ErrorCount,
    long TotalBytes,
    int ExcludedDirectoryCount)
{
    public static ScanStatistics From(IReadOnlyCollection<FileInventoryItem> files, int excludedDirectories) => new(
        files.Count,
        files.Count(f => f.Status == FileScanStatus.Hashed),
        files.Count(f => f.Status is FileScanStatus.SkippedSize or FileScanStatus.SkippedLink),
        files.Count(f => f.Status == FileScanStatus.Error),
        files.Sum(f => f.SizeBytes),
        excludedDirectories);

    public double HashedRatio => FileCount == 0 ? 0 : (double)HashedCount / FileCount;
}
