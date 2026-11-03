using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Intelligence;
using WebGuard.Core.Scanning;
using WebGuard.Intelligence;

namespace WebGuard.Tests;

public static class IntelligenceTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 2, 8, 0, 0, TimeSpan.Zero);

    private const string OsvResponse = """
        {"vulns":[{"id":"GHSA-jf85-cpcp-j695","aliases":["CVE-2019-10744"],"summary":"Prototype Pollution in lodash",
          "affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"4.17.12"}]}]}],"database_specific":{"severity":"CRITICAL"}}]}
        """;

    private static readonly string[] Values = ["a", "b"];

    private const string KevResponse = """{"vulnerabilities":[{"cveID":"CVE-2019-10744"}]}""";

    [Test]
    public static async Task Cache_round_trips_and_expires()
    {
        using var temp = new TempFolder();
        var time = new FixedTimeProvider(Now);
        var cache = new FileIntelligenceCache(temp.Path, time);
        await cache.SetAsync("k", Values, "test", CancellationToken.None);
        var hit = await cache.GetAsync<string[]>("k", TimeSpan.FromHours(1), CancellationToken.None);
        Assert.Equal("a,b", string.Join(',', hit!), "round trip");
        time.Now = Now.AddHours(2);
        Assert.Equal(null, await cache.GetAsync<string[]>("k", TimeSpan.FromHours(1), CancellationToken.None), "expired");
        Assert.Equal(null, await cache.GetAsync<string[]>("other", TimeSpan.FromHours(1), CancellationToken.None), "miss");
    }

    [Test]
    public static async Task Osv_lookup_sends_only_coordinates_flags_kev_and_caches()
    {
        using var temp = new TempFolder();
        var handler = new FakeHttpHandler(r => r.RequestUri == OsvVulnerabilityIntelligence.KevEndpoint ? KevResponse : OsvResponse);
        using var http = new HttpClient(handler);
        var allowed = true;
        var osv = new OsvVulnerabilityIntelligence(http, new FileIntelligenceCache(temp.Path), () => new IntelligenceSettings(allowed, null));
        var package = new PackageCoordinate("npm", "lodash", "4.17.11");

        var records = await osv.LookupAsync(package, CancellationToken.None);
        var r = records.Single();
        Assert.Equal(Severity.Critical, r.Severity, "severity");
        Assert.True(r.KnownExploited, "KEV flag via CVE alias");
        Assert.Equal("4.17.12", r.FixedVersions.Single(), "fixed version");
        var query = handler.Requests.Single(q => q.Uri == OsvVulnerabilityIntelligence.QueryEndpoint).Body;
        Assert.Equal("""{"version":"4.17.11","package":{"name":"lodash","ecosystem":"npm"}}""", query, "only coordinates are sent");

        allowed = false;
        var cached = await osv.LookupAsync(package, CancellationToken.None);
        Assert.Equal(1, cached.Count, "served from cache offline");
        Assert.Equal(2, handler.Requests.Count, "no extra request");
        await Assert.ThrowsAsync<InvalidOperationException>(() => osv.LookupAsync(package with { Version = "1.0.0" }, CancellationToken.None));
        Assert.Equal(EngineAvailability.Disabled, (await osv.GetStatusAsync(CancellationToken.None)).Availability, "disabled without consent");
    }

    [Test]
    public static async Task MalwareBazaar_requires_consent_and_key_and_parses_verdicts()
    {
        using var temp = new TempFolder();
        var hash = new string('a', 64);
        var handler = new FakeHttpHandler(_ => """{"query_status":"ok","data":[{"sha256_hash":"aaa","signature":"AgentTesla"}]}""");
        using var http = new HttpClient(handler);
        var settings = new IntelligenceSettings(true, null);
        var mb = new MalwareBazaarHashIntelligence(http, new FileIntelligenceCache(temp.Path), () => settings);

        Assert.Equal(EngineAvailability.NotInstalled, (await mb.GetStatusAsync(CancellationToken.None)).Availability, "needs key");
        Assert.Equal(null, await mb.LookupAsync(hash, CancellationToken.None), "no lookup without key");
        Assert.Equal(0, handler.Requests.Count, "nothing sent");

        settings = new IntelligenceSettings(true, "secret-key");
        var verdict = await mb.LookupAsync(hash.ToUpperInvariant(), CancellationToken.None);
        Assert.True(verdict!.IsKnownMalicious, "malicious");
        Assert.Equal("AgentTesla", verdict.Family, "family");
        Assert.Equal("query=get_info&hash=" + hash, handler.Requests.Single().Body, "only the hash is sent");
        Assert.Equal("secret-key", handler.Requests.Single().AuthKey, "auth header");

        Assert.True(!MalwareBazaarHashIntelligence.Parse(hash, """{"query_status":"hash_not_found"}""", Now).IsKnownMalicious, "clean");
        await Assert.ThrowsAsync<HttpRequestException>(() =>
            Task.FromResult(MalwareBazaarHashIntelligence.Parse(hash, """{"query_status":"unknown_auth_key"}""", Now)));
        await Assert.ThrowsAsync<ArgumentException>(() => mb.LookupAsync("not-a-hash", CancellationToken.None));
    }

    [Test]
    public static async Task Hash_engine_checks_only_candidate_files_and_reports_critical_malware()
    {
        var bad = new string('b', 64);
        var files = new[]
        {
            new FileInventoryItem(@"bin\drop.exe", ".exe", 10, Now, bad, FileScanStatus.Hashed, 1, null),
            new FileInventoryItem(@"web\app.js", ".js", 10, Now, new string('c', 64), FileScanStatus.Hashed, 1, null),
            new FileInventoryItem("README.md", ".md", 10, Now, new string('d', 64), FileScanStatus.Hashed, 1, null),
            new FileInventoryItem("big.zip", ".zip", 10, Now, null, FileScanStatus.SkippedSize, 0, null),
        };
        var intel = new FakeMalwareIntelligence(bad);
        var engine = new MalwareHashLookupEngine(intel);
        var result = await engine.ScanAsync(new EngineScanRequest(Guid.NewGuid(), Path.GetTempPath(), files, Path.GetTempPath(), TimeSpan.FromSeconds(10)),
            null, CancellationToken.None);

        Assert.True(result.Succeeded, "succeeded");
        Assert.Equal(2, intel.Looked.Count, "exe and js looked up; md and unhashed skipped");
        var f = result.Findings.Single();
        Assert.Equal(Severity.Critical, f.Severity, "critical");
        Assert.Equal(FindingCategory.Malware, f.Category, "malware");
        Assert.Equal(@"bin\drop.exe", f.Location.RelativePath, "location");
    }

    private sealed class FakeMalwareIntelligence(string maliciousHash) : IMalwareHashIntelligence
    {
        public List<string> Looked { get; } = [];
        public IntelligenceSourceInfo Source { get; } = new("fake", "Fake", "test", "Phase 2", false);
        public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new EngineStatus(EngineAvailability.Ready, null, null, "ok"));

        public Task<MalwareHashVerdict?> LookupAsync(string sha256, CancellationToken cancellationToken)
        {
            lock (Looked) Looked.Add(sha256);
            return Task.FromResult<MalwareHashVerdict?>(new MalwareHashVerdict(sha256, sha256 == maliciousHash, "TestFamily", "fake", Now));
        }
    }
}
