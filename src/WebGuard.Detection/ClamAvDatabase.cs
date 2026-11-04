using System.Globalization;
using System.Text;
using WebGuard.Core.Detection;

namespace WebGuard.Detection;

/// <summary>State of the ClamAV signature database Azura keeps for itself.</summary>
/// <param name="DailyVersion">Version of daily.cvd/.cld (increments several times a day).</param>
/// <param name="BuiltUtc">When the newest database part was built by Cisco Talos.</param>
/// <param name="UpdatedUtc">Last successful freshclam run (also when it found nothing new), else when the files last changed.</param>
public sealed record ClamAvDatabaseInfo(bool Present, int? DailyVersion, int? MainVersion, DateTimeOffset? BuiltUtc, DateTimeOffset? UpdatedUtc, long SizeBytes)
{
    public string Describe() => !Present
        ? "No signature database yet."
        : $"daily {DailyVersion?.ToString(CultureInfo.InvariantCulture) ?? "?"} · main {MainVersion?.ToString(CultureInfo.InvariantCulture) ?? "?"}" +
          (BuiltUtc is { } b ? $" · built {b:yyyy-MM-dd HH:mm} UTC" : string.Empty);
}

/// <summary>
/// The ClamAV signature database used by <see cref="ClamAvEngine"/>: kept under %LOCALAPPDATA%\WebGuardInspector\clamav\db
/// (no administrator rights needed) and updated with freshclam and a configuration file written by Azura.
/// </summary>
public static class ClamAvDatabase
{
    public static string DefaultRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WebGuardInspector", "clamav");

    public static string DatabaseFolder(string root) => Path.Combine(root, "db");

    public static string ConfigFile(string root) => Path.Combine(root, "freshclam.conf");

    /// <summary>Touched after every successful freshclam run, because "up-to-date" leaves the database files unchanged.</summary>
    public static string LastUpdateMarker(string databaseFolder) =>
        Path.Combine(Path.GetDirectoryName(Path.GetFullPath(databaseFolder).TrimEnd(Path.DirectorySeparatorChar)) ?? databaseFolder, "last-update");

    /// <summary>Reads the CVD/CLD headers ("ClamAV-VDB:build time:version:…") of main and daily.</summary>
    public static ClamAvDatabaseInfo Inspect(string databaseFolder)
    {
        if (!Directory.Exists(databaseFolder)) return new ClamAvDatabaseInfo(false, null, null, null, null, 0);
        var files = Directory.EnumerateFiles(databaseFolder)
            .Where(f => Path.GetExtension(f) is ".cvd" or ".cld" or ".cud")
            .Select(f => new FileInfo(f))
            .ToArray();
        var main = Header(files, "main");
        var daily = Header(files, "daily");
        if (main is null && daily is null) return new ClamAvDatabaseInfo(false, null, null, null, null, 0);
        DateTimeOffset? built = new[] { main?.Built, daily?.Built }.Where(b => b is not null).Max();
        var marker = new FileInfo(LastUpdateMarker(databaseFolder));
        var changed = files.Length == 0 ? DateTime.MinValue : files.Max(f => f.LastWriteTimeUtc);
        var last = marker.Exists && marker.LastWriteTimeUtc > changed ? marker.LastWriteTimeUtc : changed;
        DateTimeOffset? updated = last == DateTime.MinValue ? null : new DateTimeOffset(last, TimeSpan.Zero);
        return new ClamAvDatabaseInfo(main is not null && daily is not null, daily?.Version, main?.Version, built, updated, files.Sum(f => f.Length));
    }

    private static (int? Version, DateTimeOffset? Built)? Header(FileInfo[] files, string name)
    {
        var file = files.FirstOrDefault(f => Path.GetFileNameWithoutExtension(f.Name).Equals(name, StringComparison.OrdinalIgnoreCase));
        if (file is null) return null;
        var buffer = new byte[512];
        using (var stream = file.OpenRead())
        {
            var read = stream.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
            if (read < 32) return (null, null);
        }
        var parts = Encoding.ASCII.GetString(buffer).TrimEnd('\0', ' ').Split(':');
        if (parts.Length < 3 || parts[0] != "ClamAV-VDB") return (null, null);
        int? version = int.TryParse(parts[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;
        // Build time looks like "04 Nov 2026 08-26 +0000".
        DateTimeOffset? built = DateTimeOffset.TryParseExact(parts[1], "dd MMM yyyy HH-mm zzz", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal, out var b) ? b.ToUniversalTime() : null;
        return (version, built);
    }

    /// <summary>freshclam settings: Azura's own database folder and the official mirror.</summary>
    public static string WriteConfig(string root)
    {
        var db = DatabaseFolder(root);
        Directory.CreateDirectory(db);
        var path = ConfigFile(root);
        File.WriteAllText(path, string.Join("\n",
            "# Written by Azura - WebGuard Inspector. Regenerated before every update; edits are overwritten.",
            "DatabaseDirectory " + db,
            "DatabaseMirror database.clamav.net",
            "ConnectTimeout 30",
            "ReceiveTimeout 600",
            string.Empty), new UTF8Encoding(false));
        return path;
    }

    /// <summary>freshclam.exe next to clamscan.exe.</summary>
    public static string? FreshclamFor(string? clamscanPath) =>
        clamscanPath is not null && Path.GetDirectoryName(clamscanPath) is { } dir && File.Exists(Path.Combine(dir, "freshclam.exe"))
            ? Path.Combine(dir, "freshclam.exe")
            : null;

    /// <summary>Downloads or updates the signatures. Returns freshclam's summary lines; throws when it failed.</summary>
    public static async Task<string> UpdateAsync(IExternalProcessRunner runner, string freshclam, string root, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(runner);
        var config = WriteConfig(root);
        var result = await runner.RunAsync(new ProcessRunRequest(freshclam, ["--config-file=" + config, "--stdout"], root,
            TimeSpan.FromMinutes(20), 4 * 1024 * 1024), cancellationToken).ConfigureAwait(false);
        var summary = string.Join(" ", (result.StandardOutput + "\n" + result.StandardError)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(l => l.Contains("updated (version", StringComparison.Ordinal) || l.Contains("is up-to-date", StringComparison.Ordinal) ||
                        l.StartsWith("ERROR", StringComparison.Ordinal) || l.Contains("cool-down", StringComparison.OrdinalIgnoreCase)));
        if (result.TimedOut) throw new InvalidOperationException("freshclam did not finish within 20 minutes.");
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"freshclam failed (exit code {result.ExitCode}). {(summary.Length > 0 ? summary : Tail(result))}");
        await File.WriteAllTextAsync(LastUpdateMarker(DatabaseFolder(root)), DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
            cancellationToken).ConfigureAwait(false);
        return summary.Length > 0 ? summary : "Signatures are up to date.";
    }

    private static string Tail(ProcessRunResult result)
    {
        var text = (result.StandardError.Length > 0 ? result.StandardError : result.StandardOutput).Trim();
        return text.Length > 400 ? "…" + text[^400..] : text;
    }
}

/// <summary>The ClamAV database as a component Azura keeps up to date (Settings → Components, start-up check).</summary>
public sealed class ClamAvSignatureDatabase(IExternalProcessRunner runner, Func<string?> locateClamscan, string? root = null)
    : WebGuard.Core.Updates.ISignatureDatabase
{
    private readonly string _root = root ?? ClamAvDatabase.DefaultRoot;

    public string Id => "clamav-db";
    public string Name => "ClamAV signatures";

    public WebGuard.Core.Updates.SignatureDatabaseState Inspect()
    {
        var info = ClamAvDatabase.Inspect(ClamAvDatabase.DatabaseFolder(_root));
        return new(info.Present, info.Describe(), info.UpdatedUtc, ClamAvDatabase.FreshclamFor(locateClamscan()) is not null);
    }

    public Task<string> UpdateAsync(CancellationToken cancellationToken)
    {
        var freshclam = ClamAvDatabase.FreshclamFor(locateClamscan())
                        ?? throw new InvalidOperationException("freshclam.exe was not found next to clamscan.exe. Install ClamAV first.");
        return ClamAvDatabase.UpdateAsync(runner, freshclam, _root, cancellationToken);
    }
}
