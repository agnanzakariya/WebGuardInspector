using System.Text.Json;
using WebGuard.Core.Intelligence;

namespace WebGuard.Intelligence;

/// <summary>
/// CVE ids from the public CISA Known Exploited Vulnerabilities catalog. Downloading it sends no user data;
/// it is still only fetched when external lookups are allowed, and cached for 24 h for offline use.
/// </summary>
public sealed class CisaKevCatalog(HttpClient http, IIntelligenceCache cache)
{
    public const string SourceId = "cisa-kev";
    public static readonly Uri Endpoint = new("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
    private const string CacheKey = "cisa-kev";
    private static readonly TimeSpan MaxAge = TimeSpan.FromHours(24);

    /// <summary>
    /// The cached catalog, refreshed from CISA when <paramref name="allowDownload"/> is true and the cache is stale.
    /// Returns null when nothing is cached and downloading is not allowed.
    /// Throws <see cref="HttpRequestException"/> or <see cref="JsonException"/> when the download fails.
    /// </summary>
    public async Task<IReadOnlySet<string>?> GetAsync(bool allowDownload, CancellationToken cancellationToken)
    {
        var cached = await cache.GetAsync<string[]>(CacheKey, MaxAge, cancellationToken).ConfigureAwait(false);
        if (cached is not null) return cached.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!allowDownload) return null;

        using var response = await http.GetAsync(Endpoint, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var ids = Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
        await cache.SetAsync(CacheKey, ids, SourceId, cancellationToken).ConfigureAwait(false);
        return ids.ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    public static string[] Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.TryGetProperty("vulnerabilities", out var list) && list.ValueKind == JsonValueKind.Array
            ? list.EnumerateArray()
                .Select(e => e.TryGetProperty("cveID", out var id) && id.ValueKind == JsonValueKind.String ? id.GetString() : null)
                .OfType<string>()
                .ToArray()
            : [];
    }
}
