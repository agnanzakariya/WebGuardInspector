using System.Net;
using System.Text;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Scanning;
using WebGuard.Core.Updates;
using WebGuard.Detection;
using WebGuard.Intelligence;

namespace WebGuard.Tests;

public static class ClamAvTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 4, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public static void Clamscan_output_becomes_findings_by_signature_kind()
    {
        var root = Path.Combine(Path.GetTempPath(), "proj");
        var output = string.Join("\n",
            Path.Combine(root, "wp-content", "shell.php") + ": Php.Webshell.Generic-123 FOUND",
            Path.Combine(root, "tool.exe") + ": PUA.Win.Tool.Agent-1 FOUND",
            Path.Combine(root, "x.js") + ": Heuristics.Encrypted.Zip FOUND",
            "WARNING: " + Path.Combine(root, "locked.php") + ": Can't access file",
            "");
        var (findings, warnings) = ClamAvEngine.Parse(output, root, Now);

        Assert.Equal(3, findings.Count, "three detections");
        var shell = findings[0];
        Assert.True(shell is { Severity: Severity.Critical, Category: FindingCategory.Malware, Confidence: Confidence.High }, "named malware is critical");
        Assert.Equal(Path.Combine("wp-content", "shell.php"), shell.Location.RelativePath, "relative path");
        Assert.Equal("clamav.Php.Webshell.Generic-123", shell.RuleId, "rule id from the signature");
        Assert.Equal("Php.Webshell.Generic-123", shell.Evidence.Single().RedactedSnippet, "signature as evidence");
        Assert.True(findings[1] is { Severity: Severity.Medium, Category: FindingCategory.SuspiciousPattern }, "PUA is medium");
        Assert.True(findings[2].Severity == Severity.Medium, "heuristics are medium");
        Assert.True(warnings.Single().Contains("Can't access", StringComparison.Ordinal), "access problems become warnings");
    }

    [Test]
    public static void Database_headers_give_versions_and_build_time()
    {
        using var temp = new TempFolder();
        Assert.True(!ClamAvDatabase.Inspect(Path.Combine(temp.Path, "none")).Present, "missing folder");
        WriteCvd(temp.Path, "main.cvd", "ClamAV-VDB:16 Sep 2021 08-32 -0400:62:6647427:90:x:y:sigmgr:1631795735");
        Assert.True(!ClamAvDatabase.Inspect(temp.Path).Present, "main alone is not a usable database");
        WriteCvd(temp.Path, "daily.cld", "ClamAV-VDB:04 Nov 2026 08-26 +0000:28173:2084519:90:x:y:raynman:1762244781");

        var info = ClamAvDatabase.Inspect(temp.Path);
        Assert.True(info.Present, "main + daily present");
        Assert.Equal(28173, info.DailyVersion, "daily version");
        Assert.Equal(62, info.MainVersion, "main version");
        Assert.Equal(new DateTimeOffset(2026, 11, 4, 8, 26, 0, TimeSpan.Zero), info.BuiltUtc, "newest build time");
        Assert.True(info.Describe().StartsWith("daily 28173 · main 62", StringComparison.Ordinal), "description");

        var marker = ClamAvDatabase.LastUpdateMarker(temp.Path);
        File.WriteAllText(marker, "x");
        File.SetLastWriteTimeUtc(marker, new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        Assert.Equal(new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero), ClamAvDatabase.Inspect(temp.Path).UpdatedUtc,
            "an up-to-date check counts as an update");
        File.Delete(marker);

        var config = File.ReadAllText(ClamAvDatabase.WriteConfig(temp.Path));
        Assert.True(config.Contains("DatabaseDirectory " + Path.Combine(temp.Path, "db"), StringComparison.Ordinal) &&
                    config.Contains("DatabaseMirror database.clamav.net", StringComparison.Ordinal), "freshclam config points to Azura's folder");
    }

    [Test]
    public static async Task Engine_needs_signatures_and_scans_inventoried_files_with_a_bom_free_list()
    {
        using var temp = new TempFolder();
        var clamscan = temp.Write(@"ClamAV\clamscan.exe", "x");
        var project = Path.Combine(temp.Path, "proj");
        temp.Write(@"proj\a.php", "<?php");
        temp.Write(@"proj\b.php", "<?php");
        var db = Path.Combine(temp.Path, "db");
        Directory.CreateDirectory(db);
        string? listText = null;
        byte[]? listBytes = null;
        var runner = new FakeProcessRunner(r =>
        {
            if (FakeProcessRunner.IsVersionProbe(r)) return FakeProcessRunner.Ok("ClamAV 1.5.4");
            var list = r.Arguments.Single(a => a.StartsWith("--file-list=", StringComparison.Ordinal))["--file-list=".Length..];
            listBytes = File.ReadAllBytes(list);
            listText = Encoding.UTF8.GetString(listBytes);
            return FakeProcessRunner.Ok(Path.Combine(project, "b.php") + ": Php.Malware.Test-1 FOUND", exitCode: 1);
        });
        var engine = new ClamAvEngine(runner, id => new ExternalToolOptions(id, clamscan, true, []), new FixedTimeProvider(Now), () => db);

        var status = await engine.GetStatusAsync(CancellationToken.None);
        Assert.True(status.Availability == EngineAvailability.Error && status.Message!.Contains("signature", StringComparison.Ordinal), "no database yet");

        WriteCvd(db, "main.cvd", "ClamAV-VDB:16 Sep 2021 08-32 -0400:62:1:90:x:y:z:1");
        WriteCvd(db, "daily.cvd", "ClamAV-VDB:04 Nov 2026 08-26 +0000:28173:1:90:x:y:z:1");
        status = await engine.GetStatusAsync(CancellationToken.None);
        Assert.True(status.Availability == EngineAvailability.Ready && status.Message!.Contains("daily 28173", StringComparison.Ordinal), "ready with db info");

        var files = new[] { Item("a.php"), Item("b.php") };
        var result = await engine.ScanAsync(new EngineScanRequest(Guid.NewGuid(), project, files, project, TimeSpan.FromMinutes(1)), null, CancellationToken.None);
        Assert.True(result.Succeeded, "scan completed: " + result.Error);
        Assert.Equal("b.php", result.Findings.Single().Location.RelativePath, "detection mapped to the file");
        Assert.True(listBytes is [not 0xEF, ..], "file list has no byte-order mark");
        Assert.True(listText!.Contains(Path.Combine(project, "a.php"), StringComparison.Ordinal), "every inventoried file is listed");
    }

    [Test]
    public static async Task Signature_database_is_a_component_that_is_due_after_a_day()
    {
        var database = new FakeDatabase { State = new SignatureDatabaseState(false, "No signature database yet.", null, true) };
        var time = new FixedTimeProvider(Now);
        var service = new ComponentUpdateService(new HttpClient(new NotFound()), new FakeProcessRunner(_ => FakeProcessRunner.Ok("")), "tools", () => null,
            [database], time);

        var missing = (await service.CheckAsync([], CancellationToken.None)).Single();
        Assert.True(missing is { Id: "clamav-db", Source: ComponentSource.SignatureUpdater, UpdateAvailable: true, InstalledVersion: null }, "first download offered");

        database.State = new SignatureDatabaseState(true, "daily 28173", Now.AddHours(-2), true);
        Assert.True(!(await service.CheckAsync([], CancellationToken.None)).Single().UpdateAvailable, "fresh database is not due");
        time.Now = Now.AddDays(1);
        var due = (await service.CheckAsync([], CancellationToken.None)).Single();
        Assert.True(due.UpdateAvailable, "a day later it is due");

        Assert.Equal("updated", await service.UpdateAsync(due, null, CancellationToken.None), "freshclam run through the database");
        Assert.Equal(1, database.Updates, "update called once");

        database.State = new SignatureDatabaseState(false, "", null, false);
        Assert.True((await service.CheckAsync([], CancellationToken.None)).Single() is { Source: ComponentSource.Missing, CanUpdate: false },
            "without ClamAV there is nothing to update with");
    }

    [Test]
    public static async Task Daemon_mode_splits_files_across_parallel_clamdscan_clients_and_stops_clamd()
    {
        using var temp = new TempFolder();
        temp.Write(@"ClamAV\clamscan.exe", "x");
        temp.Write(@"ClamAV\clamd.exe", "x");
        temp.Write(@"ClamAV\clamdscan.exe", "x");
        var clamscan = Path.Combine(temp.Path, "ClamAV", "clamscan.exe");
        var project = Path.Combine(temp.Path, "proj");
        var names = Enumerable.Range(0, 20).Select(i => $"f{i}.php").ToArray();
        foreach (var n in names) temp.Write(@"proj\" + n, "<?php");
        var db = Path.Combine(temp.Path, "db");
        Directory.CreateDirectory(db);
        WriteCvd(db, "main.cvd", "ClamAV-VDB:16 Sep 2021 08-32 -0400:62:1:90:x:y:z:1");
        WriteCvd(db, "daily.cvd", "ClamAV-VDB:04 Nov 2026 08-26 +0000:28173:1:90:x:y:z:1");

        var runner = new DaemonRunner(project);
        var engine = new ClamAvEngine(runner, id => new ExternalToolOptions(id, clamscan, true, []), new FixedTimeProvider(Now), () => db);
        var result = await engine.ScanAsync(new EngineScanRequest(Guid.NewGuid(), project, names.Select(Item).ToArray(), project, TimeSpan.FromMinutes(1)),
            null, CancellationToken.None);

        Assert.True(result.Succeeded, "scan completed: " + result.Error);
        Assert.Equal("f7.php", result.Findings.Single().Location.RelativePath, "detection from the client that scanned f7.php");
        Assert.True(runner.Clients >= 2, "several clamdscan clients ran: " + runner.Clients);
        Assert.Equal(20, runner.ScannedFiles, "every file was sent to exactly one client");
        Assert.True(runner.DaemonStopped, "clamd was stopped after the scan");
        Assert.True(runner.Config!.Contains("TCPAddr 127.0.0.1", StringComparison.Ordinal) && runner.Config.Contains("DatabaseDirectory " + db, StringComparison.Ordinal),
            "clamd listens on loopback only and uses Azura's database");
    }

    [Test]
    public static async Task Daemon_that_does_not_start_falls_back_to_clamscan()
    {
        using var temp = new TempFolder();
        temp.Write(@"ClamAV\clamscan.exe", "x");
        temp.Write(@"ClamAV\clamd.exe", "x");
        temp.Write(@"ClamAV\clamdscan.exe", "x");
        var clamscan = Path.Combine(temp.Path, "ClamAV", "clamscan.exe");
        var project = Path.Combine(temp.Path, "proj");
        temp.Write(@"proj\a.php", "<?php");
        var db = Path.Combine(temp.Path, "db");
        Directory.CreateDirectory(db);
        WriteCvd(db, "main.cvd", "ClamAV-VDB:16 Sep 2021 08-32 -0400:62:1:90:x:y:z:1");
        WriteCvd(db, "daily.cvd", "ClamAV-VDB:04 Nov 2026 08-26 +0000:28173:1:90:x:y:z:1");
        var runner = new FakeProcessRunner(r => Path.GetFileName(r.ExecutablePath) switch
        {
            "clamd.exe" => FakeProcessRunner.Ok("ERROR: Can't bind to port", exitCode: 1),
            "clamdscan.exe" => FakeProcessRunner.Ok("", exitCode: 2),
            _ when FakeProcessRunner.IsVersionProbe(r) => FakeProcessRunner.Ok("ClamAV 1.5.4"),
            _ => FakeProcessRunner.Ok(Path.Combine(project, "a.php") + ": Php.Malware.Test-1 FOUND", exitCode: 1),
        });
        var engine = new ClamAvEngine(runner, id => new ExternalToolOptions(id, clamscan, true, []), new FixedTimeProvider(Now), () => db);
        var result = await engine.ScanAsync(new EngineScanRequest(Guid.NewGuid(), project, [Item("a.php")], project, TimeSpan.FromMinutes(1)), null, CancellationToken.None);

        Assert.True(result.Succeeded && result.Findings.Count == 1, "clamscan fallback found the file");
        Assert.True(result.Error!.Contains("clamd did not start", StringComparison.Ordinal), "the fallback is reported");
    }

    // ---- Helpers ---------------------------------------------------------------------------------------------------

    /// <summary>clamd runs until cancelled; clamdscan answers ping and reports f7.php from whichever list contains it.</summary>
    private sealed class DaemonRunner(string project) : IExternalProcessRunner
    {
        private int _clients;
        private int _scanned;
        public int Clients => _clients;
        public int ScannedFiles => _scanned;
        public bool DaemonStopped { get; private set; }
        public string? Config { get; private set; }

        public async Task<ProcessRunResult> RunAsync(ProcessRunRequest request, CancellationToken cancellationToken)
        {
            switch (Path.GetFileName(request.ExecutablePath))
            {
                case "clamd.exe":
                    Config = File.ReadAllText(request.Arguments[0]["--config-file=".Length..]);
                    try
                    {
                        await Task.Delay(Timeout.Infinite, cancellationToken);
                    }
                    finally
                    {
                        DaemonStopped = true;
                    }
                    throw new InvalidOperationException("unreachable");
                case "clamdscan.exe" when request.Arguments.Contains("--ping"):
                    return FakeProcessRunner.Ok("PONG");
                case "clamdscan.exe":
                    Interlocked.Increment(ref _clients);
                    var list = File.ReadAllLines(request.Arguments.Single(a => a.StartsWith("--file-list=", StringComparison.Ordinal))["--file-list=".Length..]);
                    Interlocked.Add(ref _scanned, list.Length);
                    var hit = list.FirstOrDefault(l => l.EndsWith("f7.php", StringComparison.Ordinal));
                    return hit is null ? FakeProcessRunner.Ok("") : FakeProcessRunner.Ok(Path.Combine(project, "f7.php") + ": Php.Malware.Test-1 FOUND", exitCode: 1);
                default:
                    return FakeProcessRunner.Ok("ClamAV 1.5.4");
            }
        }
    }

    private static FileInventoryItem Item(string path) => new(path, Path.GetExtension(path), 5, Now, null, FileScanStatus.Hashed, 0, null);

    private static void WriteCvd(string folder, string name, string header)
    {
        var bytes = new byte[600];
        Encoding.ASCII.GetBytes(header.PadRight(512)).CopyTo(bytes, 0);
        File.WriteAllBytes(Path.Combine(folder, name), bytes);
    }

    private sealed class FakeDatabase : ISignatureDatabase
    {
        public SignatureDatabaseState State { get; set; } = new(false, "", null, true);
        public int Updates { get; private set; }
        public string Id => "clamav-db";
        public string Name => "ClamAV signatures";
        public SignatureDatabaseState Inspect() => State;

        public Task<string> UpdateAsync(CancellationToken cancellationToken)
        {
            Updates++;
            return Task.FromResult("updated");
        }
    }

    private sealed class NotFound : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}
