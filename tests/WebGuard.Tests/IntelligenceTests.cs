using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Intelligence;
using WebGuard.Core.Scanning;
using WebGuard.Intelligence;
using WebGuard.Scanner;

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
        var handler = new FakeHttpHandler(r => r.RequestUri == CisaKevCatalog.Endpoint ? KevResponse : OsvResponse);
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
        var bazaar = new FakeMalwareIntelligence("bazaar", bad);
        var threatFox = new FakeMalwareIntelligence("threatfox", bad, family: null);
        var offline = new FakeMalwareIntelligence("offline", bad, ready: false);
        var engine = new MalwareHashLookupEngine([bazaar, threatFox, offline]);
        var result = await engine.ScanAsync(new EngineScanRequest(Guid.NewGuid(), Path.GetTempPath(), files, Path.GetTempPath(), TimeSpan.FromSeconds(10)),
            null, CancellationToken.None);

        Assert.True(result.Succeeded, "succeeded");
        Assert.Equal(2, bazaar.Looked.Count, "exe and js looked up; md and unhashed skipped");
        Assert.Equal(2, threatFox.Looked.Count, "every ready source is queried");
        Assert.Equal(0, offline.Looked.Count, "a source that is not ready is never queried");
        var f = result.Findings.Single();
        Assert.Equal(Severity.Critical, f.Severity, "critical");
        Assert.Equal(FindingCategory.Malware, f.Category, "malware");
        Assert.Equal(@"bin\drop.exe", f.Location.RelativePath, "location");
        Assert.Equal("Known malware: TestFamily", f.Title, "family from the source that has one");
        Assert.Equal("bazaar|threatfox", string.Join('|', f.Evidence.Select(e => e.Source)), "one finding, evidence per source");
        Assert.True(f.Description.Contains("bazaar and threatfox", StringComparison.Ordinal), "both sources named");
    }

    [Test]
    public static async Task ThreatFox_sends_only_the_hash_and_parses_verdicts()
    {
        using var temp = new TempFolder();
        var hash = new string('e', 64);
        var handler = new FakeHttpHandler(_ => """{"query_status":"ok","data":[{"ioc":"x","malware":"win.agent_tesla","malware_printable":"Agent Tesla"}]}""");
        using var http = new HttpClient(handler);
        var tf = new ThreatFoxHashIntelligence(http, new FileIntelligenceCache(temp.Path), () => new IntelligenceSettings(true, "key-1"));

        var verdict = await tf.LookupAsync(hash, CancellationToken.None);
        Assert.True(verdict!.IsKnownMalicious, "malicious");
        Assert.Equal("Agent Tesla", verdict.Family, "printable family");
        var sent = handler.Requests.Single();
        Assert.Equal(ThreatFoxHashIntelligence.Endpoint, sent.Uri, "endpoint");
        Assert.Equal("""{"query":"search_hash","hash":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}""", sent.Body, "only the hash is sent");
        Assert.Equal("key-1", sent.AuthKey, "auth header");
        await tf.LookupAsync(hash, CancellationToken.None);
        Assert.Equal(1, handler.Requests.Count, "second lookup served from cache");

        Assert.True(!ThreatFoxHashIntelligence.Parse(hash, """{"query_status":"no_result","data":"Your search did not yield any results"}""", Now).IsKnownMalicious, "clean");
        await Assert.ThrowsAsync<HttpRequestException>(() =>
            Task.FromResult(ThreatFoxHashIntelligence.Parse(hash, """{"query_status":"unknown_auth_key"}""", Now)));
        // A file listed as a sha256_hash IOC is not a payload hash: only search_ioc finds it.
        var iocHash = new string('f', 64);
        var fallback = new FakeHttpHandler(r => r.Content!.ReadAsStringAsync().Result.Contains("search_ioc", StringComparison.Ordinal)
            ? """{"query_status":"ok","data":[{"ioc":"ffff","ioc_type":"sha256_hash","malware_printable":"Cobalt Strike"}]}"""
            : """{"query_status":"no_result"}""");
        using var fallbackHttp = new HttpClient(fallback);
        var tf2 = new ThreatFoxHashIntelligence(fallbackHttp, new FileIntelligenceCache(Path.Combine(temp.Path, "c2")), () => new IntelligenceSettings(true, "key-1"));
        var ioc = await tf2.LookupAsync(iocHash, CancellationToken.None);
        Assert.True(ioc!.IsKnownMalicious, "found via search_ioc");
        Assert.Equal("Cobalt Strike", ioc.Family, "family from IOC");
        Assert.Equal("""{"query":"search_ioc","search_term":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","exact_match":true}""",
            fallback.Requests[1].Body, "exact IOC search with only the hash");

        var off = new ThreatFoxHashIntelligence(http, new FileIntelligenceCache(temp.Path), () => IntelligenceSettings.Offline);
        Assert.Equal(EngineAvailability.Disabled, (await off.GetStatusAsync(CancellationToken.None)).Availability, "consent required");
    }

    [Test]
    public static void Kev_marks_exploited_cves_critical_and_keeps_fingerprint()
    {
        var finding = DependencyFinding("GHSA-aaaa", "CVE-2021-44228");
        var marked = KnownExploitedEnricher.Mark(finding, new HashSet<string>(["cve-2021-44228"], StringComparer.OrdinalIgnoreCase));
        Assert.Equal(Severity.Critical, marked.Severity, "raised to critical");
        Assert.Equal(finding.Fingerprint, marked.Fingerprint, "identity unchanged");
        Assert.Equal("CVE-2021-44228", marked.Evidence.Single(e => e.Kind == KnownExploitedEnricher.EvidenceKind).RedactedSnippet, "KEV evidence");
        Assert.True(marked.Description.Contains("Original severity: High", StringComparison.Ordinal), "original severity kept");
        Assert.True(ReferenceEquals(marked, KnownExploitedEnricher.Mark(marked, new HashSet<string>(["CVE-2021-44228"]))), "idempotent");
        var other = DependencyFinding("GHSA-bbbb", "CVE-2020-0001");
        Assert.True(ReferenceEquals(other, KnownExploitedEnricher.Mark(other, new HashSet<string>(["CVE-2021-44228"]))), "untouched when not listed");
    }

    [Test]
    public static async Task Scanner_applies_kev_enricher_after_engines()
    {
        using var temp = new TempFolder();
        temp.Write("package-lock.json", "{}");
        temp.Write("app.js", "x");
        var handler = new FakeHttpHandler(_ => KevResponse);
        using var http = new HttpClient(handler);
        var allowed = true;
        var enricher = new KnownExploitedEnricher(new CisaKevCatalog(http, new FileIntelligenceCache(Path.Combine(temp.Path, "cache"))),
            () => new IntelligenceSettings(allowed, null));
        var engine = new FixedEngine([DependencyFinding("GHSA-jf85-cpcp-j695", "CVE-2019-10744"), DependencyFinding("GHSA-x", "CVE-2000-1")]);

        var report = await new LocalFolderScanner([engine], [enricher]).ScanAsync(temp.Path, ScanOptions.Default, null, CancellationToken.None);
        Assert.Equal(Severity.Critical, report.Findings[0].Severity, "KEV finding sorted first as critical");
        Assert.Equal("GHSA-jf85-cpcp-j695", report.Findings[0].RuleId, "the listed CVE");
        Assert.Equal(Severity.High, report.Findings[1].Severity, "unlisted unchanged");
        var kev = report.Engines.Single(e => e.EngineId == CisaKevCatalog.SourceId);
        Assert.Equal("Completed", kev.Outcome, "enricher summary");
        Assert.Equal(1, kev.FindingCount, "one flagged");

        allowed = false;
        var offline = await new LocalFolderScanner([engine], [enricher]).ScanAsync(temp.Path, ScanOptions.Default, null, CancellationToken.None);
        Assert.Equal("Disabled", offline.Engines.Single(e => e.EngineId == CisaKevCatalog.SourceId).Outcome, "consent respected");
        Assert.True(offline.Findings.All(f => f.Severity == Severity.High), "no enrichment without consent");

        var rogue = await new LocalFolderScanner([engine], [new RogueEnricher()]).ScanAsync(temp.Path, ScanOptions.Default, null, CancellationToken.None);
        Assert.Equal("Failed", rogue.Engines.Single(e => e.EngineId == "rogue").Outcome, "enricher may not change identities");
        Assert.Equal(2, rogue.Findings.Count, "findings kept");
    }

    private static SecurityFinding DependencyFinding(string id, string cve) => new(
        Guid.NewGuid(), FindingFingerprint.Compute("osv-scanner", id, "package-lock.json", "npm/lodash@4.17.11"), "osv-scanner", id,
        "lodash 4.17.11: issue", "desc.", FindingCategory.VulnerableDependency, Severity.High, Confidence.High, FindingOrigin.Engine,
        new SourceLocation("package-lock.json", 0, 0), [], [], [id, cve], "Upgrade.", ValidationStatus.New, Now);

    private sealed class FixedEngine(IReadOnlyList<SecurityFinding> findings) : ISecurityEngine
    {
        public SecurityEngineInfo Info { get; } = new("fixed", "Fixed", EngineKind.DependencyAudit, "test", "Phase 2", null);
        public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new EngineStatus(EngineAvailability.Ready, "1", null, "ok"));
        public Task<EngineScanResult> ScanAsync(EngineScanRequest request, IProgress<EngineProgress>? progress, CancellationToken cancellationToken) =>
            Task.FromResult(new EngineScanResult("fixed", true, findings, TimeSpan.Zero, null, null));
    }

    private sealed class RogueEnricher : IFindingEnricher
    {
        public SecurityEngineInfo Info { get; } = new("rogue", "Rogue", EngineKind.DependencyAudit, "test", "Phase 2", null);
        public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new EngineStatus(EngineAvailability.Ready, null, null, "ok"));
        public Task<EnrichmentResult> EnrichAsync(IReadOnlyList<SecurityFinding> findings, CancellationToken cancellationToken) =>
            Task.FromResult(new EnrichmentResult(findings.Select(f => f with { Fingerprint = "changed" }).ToArray(), findings.Count, "x"));
    }

    private sealed class FakeMalwareIntelligence(string id, string maliciousHash, bool ready = true, string? family = "TestFamily") : IMalwareHashIntelligence
    {
        public List<string> Looked { get; } = [];
        public IntelligenceSourceInfo Source { get; } = new(id, id, "test", "Phase 2", false);
        public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new EngineStatus(ready ? EngineAvailability.Ready : EngineAvailability.Disabled, null, null, "ok"));

        public Task<MalwareHashVerdict?> LookupAsync(string sha256, CancellationToken cancellationToken)
        {
            lock (Looked) Looked.Add(sha256);
            return Task.FromResult<MalwareHashVerdict?>(new MalwareHashVerdict(sha256, sha256 == maliciousHash, family, id, Now));
        }
    }
}
