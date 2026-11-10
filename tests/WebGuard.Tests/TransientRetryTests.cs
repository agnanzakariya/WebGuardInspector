using System.Net;
using System.Text;
using WebGuard.Core.Detection;
using WebGuard.Core.Intelligence;
using WebGuard.Core.Scanning;
using WebGuard.Intelligence;

namespace WebGuard.Tests;

/// <summary>Temporary errors of online services (502 Bad Gateway and the like) are retried before a lookup fails.</summary>
public static class TransientRetryTests
{
    private static readonly string Hash = new('b', 64);

    [Test]
    public static async Task Bad_gateway_is_retried_and_the_lookup_succeeds()
    {
        using var temp = new TempFolder();
        var handler = new SequenceHandler(HttpStatusCode.BadGateway, HttpStatusCode.ServiceUnavailable, HttpStatusCode.OK);
        using var http = new HttpClient(handler);
        var mb = new MalwareBazaarHashIntelligence(http, new FileIntelligenceCache(temp.Path), () => new IntelligenceSettings(true, "key"),
            retry: TransientRetry.Immediate);

        var verdict = await mb.LookupAsync(Hash, CancellationToken.None);
        Assert.True(verdict is { IsKnownMalicious: false }, "answered after two temporary errors");
        Assert.True(handler.Calls == 3 && handler.AuthKeys.All(k => k == "key"), "three attempts, each a complete request with the Auth-Key");
    }

    [Test]
    public static async Task Lasting_errors_and_client_errors_fail_with_a_clear_warning()
    {
        using var temp = new TempFolder();
        var always = new SequenceHandler(HttpStatusCode.BadGateway);
        using var http = new HttpClient(always);
        var mb = new MalwareBazaarHashIntelligence(http, new FileIntelligenceCache(temp.Path), () => new IntelligenceSettings(true, "key"),
            retry: TransientRetry.Immediate);
        HttpRequestException? failed = null;
        try
        {
            await mb.LookupAsync(Hash, CancellationToken.None);
        }
        catch (HttpRequestException ex)
        {
            failed = ex;
        }
        Assert.True(failed is not null, "lasting error reported");
        Assert.Equal(3, always.Calls, "retried twice, then gave up");
        Assert.Equal("502 Bad Gateway (temporary problem at the service)", MalwareHashLookupEngine.Describe(failed!), "readable reason");

        var forbidden = new SequenceHandler(HttpStatusCode.Forbidden);
        using var http2 = new HttpClient(forbidden);
        var mb2 = new MalwareBazaarHashIntelligence(http2, new FileIntelligenceCache(Path.Combine(temp.Path, "2")), () => new IntelligenceSettings(true, "key"),
            retry: TransientRetry.Immediate);
        await Assert.ThrowsAsync<HttpRequestException>(() => mb2.LookupAsync(Hash, CancellationToken.None));
        Assert.Equal(1, forbidden.Calls, "a client error (wrong key) is not retried");

        var engine = new MalwareHashLookupEngine([mb]);
        var result = await engine.ScanAsync(new EngineScanRequest(Guid.NewGuid(), temp.Path,
            [new FileInventoryItem("a.php", ".php", 1, null, Hash, FileScanStatus.Hashed, 0, null)], temp.Path, TimeSpan.FromMinutes(1)), null, CancellationToken.None);
        Assert.True(!result.Succeeded && result.Error!.Contains("MalwareBazaar (abuse.ch): 1 × 502 Bad Gateway (temporary problem at the service)", StringComparison.Ordinal) &&
                    result.Error.Contains("looked up again in the next scan", StringComparison.Ordinal), "warning says what failed and what happens next: " + result.Error);
    }

    /// <summary>Answers with the given status codes in turn (the last one repeats); OK returns "hash not found".</summary>
    private sealed class SequenceHandler(params HttpStatusCode[] codes) : HttpMessageHandler
    {
        public int Calls { get; private set; }
        public List<string?> AuthKeys { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var code = codes[Math.Min(Calls, codes.Length - 1)];
            Calls++;
            AuthKeys.Add(request.Headers.TryGetValues("Auth-Key", out var v) ? v.Single() : null);
            return Task.FromResult(new HttpResponseMessage(code)
            {
                Content = new StringContent(code == HttpStatusCode.OK ? """{"query_status":"hash_not_found"}""" : "error", Encoding.UTF8, "application/json"),
            });
        }
    }
}
