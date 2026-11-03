using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WebGuard.Core.Intelligence;

namespace WebGuard.Intelligence;

/// <summary>
/// One JSON file per cache key under %LOCALAPPDATA%\WebGuardInspector\intel-cache, recording the source and
/// retrieval time so results stay auditable and usable offline. Keys are hashed into file names.
/// </summary>
public sealed class FileIntelligenceCache(string directory, TimeProvider? timeProvider = null) : IIntelligenceCache
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    public static string DefaultDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WebGuardInspector", "intel-cache");

    public string Directory { get; } = directory;

    public async Task<T?> GetAsync<T>(string key, TimeSpan maxAge, CancellationToken cancellationToken) where T : class
    {
        var path = PathFor(key);
        if (!File.Exists(path)) return null;
        try
        {
            var stream = File.OpenRead(path);
            await using (stream.ConfigureAwait(false))
            {
                var entry = await JsonSerializer.DeserializeAsync<Entry<T>>(stream, Options, cancellationToken).ConfigureAwait(false);
                if (entry is null || entry.Key != key || _time.GetUtcNow() - entry.RetrievedAtUtc > maxAge) return null;
                return entry.Value;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    public async Task SetAsync<T>(string key, T value, string sourceId, CancellationToken cancellationToken) where T : class
    {
        System.IO.Directory.CreateDirectory(Directory);
        var path = PathFor(key);
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var stream = File.Create(temp);
            await using (stream.ConfigureAwait(false))
            {
                await JsonSerializer.SerializeAsync(stream, new Entry<T>(key, sourceId, _time.GetUtcNow(), value), Options, cancellationToken)
                    .ConfigureAwait(false);
            }
            File.Move(temp, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A cache write failure must never fail a scan.
            try { File.Delete(temp); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    private string PathFor(string key) =>
        Path.Combine(Directory, Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(key))) + ".json");

    private sealed record Entry<T>(string Key, string SourceId, DateTimeOffset RetrievedAtUtc, T Value);
}
