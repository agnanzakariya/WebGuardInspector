namespace WebGuard.Core.Updates;

/// <summary>The newest published release and its installer.</summary>
/// <param name="Sha256">Lower-case hex SHA-256 of the installer published with the release; null when none was published.</param>
public sealed record ReleaseInfo(
    string Version,
    string Tag,
    string Name,
    string Notes,
    Uri PageUrl,
    DateTimeOffset? PublishedAtUtc,
    Uri? SetupUrl,
    string? SetupFileName,
    long? SetupSize,
    string? Sha256);

/// <param name="IsNewer">The release is newer than the running version.</param>
public sealed record UpdateCheckResult(string CurrentVersion, ReleaseInfo? Latest, bool IsNewer, string? Error, DateTimeOffset CheckedAtUtc);

public interface IUpdateService
{
    /// <summary>Where releases are published (shown in the UI).</summary>
    Uri ReleasesPage { get; }

    Task<UpdateCheckResult> CheckAsync(CancellationToken cancellationToken);

    /// <summary>Downloads the installer and verifies its SHA-256. Returns the local path; throws when it does not match.</summary>
    Task<string> DownloadAsync(ReleaseInfo release, IProgress<double>? progress, CancellationToken cancellationToken);
}

public static class AppVersion
{
    /// <summary>Parses "v1.2.3", "1.2" or "1.2.3-beta" (pre-release suffix ignored) into a comparable version.</summary>
    public static Version? Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var core = text.Trim().TrimStart('v', 'V').Split('-', '+')[0];
        if (!Version.TryParse(core, out var v)) return null;
        // Normalise "1.2" to "1.2.0" so it compares equal to "1.2.0".
        return new Version(v.Major, v.Minor, Math.Max(0, v.Build), Math.Max(0, v.Revision));
    }

    public static bool IsNewer(string? candidate, string current) =>
        Parse(candidate) is { } c && Parse(current) is { } cur && c > cur;
}
