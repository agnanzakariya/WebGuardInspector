using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using WebGuard.Core.Detection;
using WebGuard.Core.Intelligence;

namespace WebGuard.Intelligence;

/// <summary>
/// SHA-256 lookup against the abuse.ch ThreatFox IOC database (payloads seen in active campaigns).
/// Sends only the hash, only with consent and an Auth-Key; hits and misses are cached like MalwareBazaar's.
/// </summary>
public sealed class ThreatFoxHashIntelligence(
    HttpClient http,
    IIntelligenceCache cache,
    Func<IntelligenceSettings> settings,
    TimeProvider? timeProvider = null) : IMalwareHashIntelligence
{
    public const string SourceId = "threatfox";
    public static readonly Uri Endpoint = new("https://threatfox-api.abuse.ch/api/v1/");
    private static readonly TimeSpan MaxAge = TimeSpan.FromDays(3);
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    public IntelligenceSourceInfo Source { get; } = new(SourceId, "ThreatFox (abuse.ch)",
        "IOCs from active malware campaigns, matched by SHA-256 (hash only, with consent)", "Phase 2", SendsDataExternally: true);

    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
        Task.FromResult(settings().AbuseChStatus("Sends SHA-256 hashes only; IOC matches cached for 3 days."));

    public async Task<MalwareHashVerdict?> LookupAsync(string sha256, CancellationToken cancellationToken)
    {
        if (sha256 is not { Length: 64 } || !sha256.All(Uri.IsHexDigit))
            throw new ArgumentException("A 64-character hex SHA-256 is required.", nameof(sha256));
        var hash = sha256.ToLowerInvariant();
        var key = "tf:" + hash;
        var cached = await cache.GetAsync<MalwareHashVerdict>(key, MaxAge, cancellationToken).ConfigureAwait(false);
        if (cached is not null) return cached;

        var s = settings();
        if (!s.AllowExternalLookups || string.IsNullOrWhiteSpace(s.AbuseChAuthKey)) return null;

        using var request = new HttpRequestMessage(HttpMethod.Post, Endpoint)
        {
            Content = JsonContent.Create(new SearchHash("search_hash", hash)),
        };
        request.Headers.Add("Auth-Key", s.AbuseChAuthKey.Trim());
        using var response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var verdict = Parse(hash, await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false), _time.GetUtcNow());
        await cache.SetAsync(key, verdict, SourceId, cancellationToken).ConfigureAwait(false);
        return verdict;
    }

    public static MalwareHashVerdict Parse(string sha256, string json, DateTimeOffset retrievedAtUtc)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        var status = root.TryGetProperty("query_status", out var s) ? s.GetString() : null;
        switch (status)
        {
            case "ok":
                string? family = null;
                if (root.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array && data.GetArrayLength() > 0)
                {
                    var first = data[0];
                    family = Str(first, "malware_printable") ?? Str(first, "malware");
                }
                return new MalwareHashVerdict(sha256, true, family, SourceId, retrievedAtUtc);
            case "no_result" or "no_results" or "hash_not_found":
                return new MalwareHashVerdict(sha256, false, null, SourceId, retrievedAtUtc);
            default:
                // e.g. "unknown_auth_key", "illegal_hash": surface it instead of caching a false negative.
                throw new HttpRequestException("ThreatFox returned: " + (status ?? "unexpected response"));
        }
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } text ? text : null;

    private sealed record SearchHash(
        [property: JsonPropertyName("query")] string Query,
        [property: JsonPropertyName("hash")] string Hash);
}
