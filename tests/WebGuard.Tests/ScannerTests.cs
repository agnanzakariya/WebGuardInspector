using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WebGuard.Core.Scanning;
using WebGuard.Detection;
using WebGuard.Scanner;

namespace WebGuard.Tests;

public static class ScannerTests
{
    private static string Sha(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    [Test]
    public static async Task Inventory_hashes_files_and_skips_excluded_directories()
    {
        using var temp = new TempFolder();
        temp.Write("hello.txt", "Hello WebGuard");
        temp.Write("src/app.cs", "class A {}");
        temp.Write(".git/ignored.txt", "ignored");
        temp.Write("node_modules/pkg/index.js", "ignored");
        temp.Write("bin/Debug/app.dll", "ignored");

        var report = await new LocalFolderScanner().ScanAsync(temp.Path, ScanOptions.Default, null, CancellationToken.None);

        Assert.Equal(2, report.Statistics.FileCount, "file count");
        Assert.Equal(2, report.Statistics.HashedCount, "hashed count");
        Assert.Equal(0, report.Statistics.ErrorCount, "error count");
        Assert.Equal(3, report.Statistics.ExcludedDirectoryCount, "excluded dirs");
        Assert.Equal(Sha("Hello WebGuard"), report.Files.Single(f => f.RelativePath == "hello.txt").Sha256, "sha256");
        Assert.Equal(ScanReport.CurrentSchemaVersion, report.SchemaVersion, "schema");
    }

    [Test]
    public static async Task Files_are_sorted_deterministically_even_with_parallel_hashing()
    {
        using var temp = new TempFolder();
        foreach (var n in new[] { "b.txt", "A.txt", "c/z.txt", "c/a.txt", "D.txt" }) temp.Write(n, n);

        var options = ScanOptions.Default with { MaxDegreeOfParallelism = 4 };
        var report = await new LocalFolderScanner().ScanAsync(temp.Path, options, null, CancellationToken.None);
        var paths = report.Files.Select(f => f.RelativePath.Replace('\\', '/')).ToArray();
        Assert.Equal("A.txt|b.txt|c/a.txt|c/z.txt|D.txt", string.Join('|', paths), "order");
    }

    [Test]
    public static async Task Files_over_limit_are_inventoried_but_not_hashed()
    {
        using var temp = new TempFolder();
        temp.Write("big.bin", new string('x', 2048));
        temp.Write("small.txt", "ok");

        var options = ScanOptions.Default with { MaxHashBytes = 1024 };
        var report = await new LocalFolderScanner().ScanAsync(temp.Path, options, null, CancellationToken.None);
        var big = report.Files.Single(f => f.RelativePath == "big.bin");
        Assert.Equal(FileScanStatus.SkippedSize, big.Status, "status");
        Assert.Equal(null, big.Sha256, "hash");
        Assert.Equal(2048L, big.SizeBytes, "size");
        Assert.Equal(1, report.Statistics.SkippedCount, "skipped");
    }

    [Test]
    public static async Task Custom_exclusions_are_honoured_case_insensitively()
    {
        using var temp = new TempFolder();
        temp.Write("Vendor/lib.js", "x");
        temp.Write("app.js", "y");
        var options = ScanOptions.Default with { ExcludedDirectories = ["vendor"] };
        var report = await new LocalFolderScanner().ScanAsync(temp.Path, options, null, CancellationToken.None);
        Assert.Equal(1, report.Statistics.FileCount, "file count");
    }

    [Test]
    public static async Task Cancellation_stops_the_scan()
    {
        using var temp = new TempFolder();
        for (var i = 0; i < 50; i++) temp.Write($"f{i}.txt", new string('a', 1000));
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            new LocalFolderScanner().ScanAsync(temp.Path, ScanOptions.Default, null, cts.Token));
    }

    [Test]
    public static async Task Missing_folder_throws()
    {
        await Assert.ThrowsAsync<DirectoryNotFoundException>(() =>
            new LocalFolderScanner().ScanAsync(Path.Combine(Path.GetTempPath(), "does-not-exist-" + Guid.NewGuid()), ScanOptions.Default, null, CancellationToken.None));
    }

    [Test]
    public static async Task Progress_reaches_completed_phase()
    {
        using var temp = new TempFolder();
        temp.Write("a.txt", "a");
        var phases = new List<ScanPhase>();
        var progress = new SyncProgress<ScanProgress>(p => phases.Add(p.Phase));
        await new LocalFolderScanner().ScanAsync(temp.Path, ScanOptions.Default, progress, CancellationToken.None);
        Assert.True(phases.Contains(ScanPhase.Discovering), "discovering reported");
        Assert.Equal(ScanPhase.Completed, phases[^1], "last phase");
    }

    [Test]
    public static async Task Report_lists_engine_outcomes_and_round_trips_as_json()
    {
        using var temp = new TempFolder();
        temp.Write("a.txt", "a");
        var report = await new LocalFolderScanner(TestEngines.Offline())
            .ScanAsync(temp.Path, ScanOptions.Default, null, CancellationToken.None);

        Assert.Equal(5, report.Engines.Count, "engines (the five CLI engines)");
        Assert.True(report.Engines.All(e => e.Outcome == "Disabled"), "all disabled");

        using var stream = new MemoryStream();
        await new JsonReportExporter().ExportAsync(report, stream, CancellationToken.None);
        var json = Encoding.UTF8.GetString(stream.ToArray());
        Assert.True(json.Contains("\"schemaVersion\": \"1.1\"", StringComparison.Ordinal), "camelCase schema field");
        Assert.True(json.Contains("\"status\": \"Hashed\"", StringComparison.Ordinal), "enum as string");
        var back = JsonSerializer.Deserialize<ScanReport>(json, JsonReportExporter.SerializerOptions)!;
        Assert.Equal(report.ScanId, back.ScanId, "scan id");
        Assert.Equal(report.Files[0].Sha256, back.Files[0].Sha256, "hash round trip");
    }

    [Test]
    public static async Task History_store_returns_newest_first_and_respects_capacity()
    {
        using var temp = new TempFolder();
        temp.Write("a.txt", "a");
        var store = new InMemoryScanHistoryStore(capacity: 2);
        var scanner = new LocalFolderScanner();
        var ids = new List<Guid>();
        for (var i = 0; i < 3; i++)
        {
            var r = await scanner.ScanAsync(temp.Path, ScanOptions.Default, null, CancellationToken.None);
            ids.Add(r.ScanId);
            await store.AddAsync(r);
        }
        var recent = await store.GetRecentAsync(10);
        Assert.Equal(2, recent.Count, "capacity");
        Assert.Equal(ids[2], recent[0].ScanId, "newest first");
    }
}

/// <summary>IProgress that invokes synchronously (Progress&lt;T&gt; posts to the thread pool in a console app).</summary>
public sealed class SyncProgress<T>(Action<T> handler) : IProgress<T>
{
    public void Report(T value) => handler(value);
}
