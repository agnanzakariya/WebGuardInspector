using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WebGuard.Core.Scanning;

namespace WebGuard.Scanner;

/// <summary>
/// One JSON file per scanned folder under %LOCALAPPDATA%\WebGuardInspector\scan-cache. Only file identities and
/// findings (already redacted) are stored, never file contents. A damaged or unreadable cache is treated as empty.
/// </summary>
public sealed class FileScanResultCacheStore(string directory) : IScanResultCacheStore
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    public static string DefaultDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WebGuardInspector", "scan-cache");

    public string Directory { get; } = directory;

    public async Task<ScanResultCache?> LoadAsync(string rootFolder, CancellationToken cancellationToken)
    {
        var path = PathFor(rootFolder);
        try
        {
            if (!File.Exists(path)) return null;
            var stream = File.OpenRead(path);
            await using (stream.ConfigureAwait(false))
            {
                var cache = await JsonSerializer.DeserializeAsync<ScanResultCache>(stream, Json, cancellationToken).ConfigureAwait(false);
                return cache is not null && string.Equals(Normalize(cache.RootFolder), Normalize(rootFolder), StringComparison.OrdinalIgnoreCase)
                    ? cache with
                    {
                        Files = new Dictionary<string, string>(cache.Files, StringComparer.OrdinalIgnoreCase),
                        Engines = new Dictionary<string, EngineResultCache>(cache.Engines, StringComparer.Ordinal),
                    }
                    : null;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
        {
            return null;
        }
    }

    public async Task SaveAsync(ScanResultCache cache, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(cache);
        var path = PathFor(cache.RootFolder);
        var temp = path + ".tmp";
        try
        {
            System.IO.Directory.CreateDirectory(Directory);
            var stream = File.Create(temp);
            await using (stream.ConfigureAwait(false))
            {
                await JsonSerializer.SerializeAsync(stream, cache, Json, cancellationToken).ConfigureAwait(false);
            }
            File.Move(temp, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // Only a cache: the next scan runs in full.
            try { File.Delete(temp); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    public void Clear()
    {
        if (!System.IO.Directory.Exists(Directory)) return;
        foreach (var file in System.IO.Directory.EnumerateFiles(Directory, "*.json"))
        {
            try { File.Delete(file); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    private string PathFor(string rootFolder) => Path.Combine(Directory,
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Normalize(rootFolder).ToUpperInvariant())))[..24] + ".json");

    private static string Normalize(string root) => Path.GetFullPath(root).TrimEnd('\\', '/');
}
