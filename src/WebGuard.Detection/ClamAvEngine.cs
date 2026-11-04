using System.Text;
using System.Text.RegularExpressions;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;

namespace WebGuard.Detection;

/// <summary>
/// ClamAV (Cisco Talos) antivirus scan of every inventoried file with clamscan and the signature database Azura keeps
/// up to date (<see cref="ClamAvDatabase"/>). Files are only read; nothing is quarantined or deleted.
/// </summary>
public sealed partial class ClamAvEngine(IExternalProcessRunner runner, Func<string, ExternalToolOptions>? options = null,
    TimeProvider? timeProvider = null, Func<string>? databaseFolder = null)
    : ExternalToolEngine(runner, options, timeProvider)
{
    public const string Id = "clamav";
    private readonly Func<string> _databaseFolder = databaseFolder ?? (() => ClamAvDatabase.DatabaseFolder(ClamAvDatabase.DefaultRoot));

    public override SecurityEngineInfo Info { get; } = new(
        Id, "ClamAV", EngineKind.MalwareSignature,
        "Antivirus scan with ClamAV signatures (Cisco Talos); files are only read.",
        "Phase 2", "https://www.clamav.net/");

    protected override IReadOnlyList<string> ExecutableNames => ["clamscan"];

    protected override string InstallHint => "Install ClamAV (winget install Cisco.ClamAV) or set the path to clamscan.exe in Settings.";

    protected override string? MissingPrerequisite() => ClamAvDatabase.Inspect(_databaseFolder()).Present
        ? null
        : "No ClamAV signature database yet. Download it in Settings → Components (ClamAV signatures).";

    /// <summary>clamscan takes a file list, so only changed files are listed. New signatures invalidate the cache.</summary>
    public override IncrementalScanMode IncrementalMode => IncrementalScanMode.ChangedFilesList;

    protected override IEnumerable<string> AdditionalStampFiles()
    {
        var folder = _databaseFolder();
        return Directory.Exists(folder)
            ? Directory.EnumerateFiles(folder).Where(f => Path.GetExtension(f) is ".cvd" or ".cld" or ".cud")
            : [];
    }

    protected override string ReadyMessage(string executablePath) =>
        $"{executablePath} · {ClamAvDatabase.Inspect(_databaseFolder()).Describe()}";

    /// <summary>Waiting for clamd to load the signatures (about 20 s for the official database).</summary>
    private static readonly TimeSpan DaemonStartTimeout = TimeSpan.FromSeconds(120);

    protected override async Task<IReadOnlyList<SecurityFinding>> RunAsync(EngineInvocation invocation, CancellationToken cancellationToken)
    {
        var root = invocation.Request.RootFolder;
        var files = invocation.Request.Files.Select(f => Path.Combine(root, f.RelativePath)).Where(File.Exists).ToArray();
        if (files.Length == 0) return [];

        var work = Path.Combine(Path.GetTempPath(), $"webguard-clamav-{invocation.Request.ScanId:N}");
        Directory.CreateDirectory(work);
        try
        {
            var folder = Path.GetDirectoryName(invocation.ExecutablePath)!;
            var clamd = Path.Combine(folder, "clamd.exe");
            var clamdscan = Path.Combine(folder, "clamdscan.exe");
            if (File.Exists(clamd) && File.Exists(clamdscan))
            {
                var daemon = await ScanWithDaemonAsync(invocation, clamd, clamdscan, files, work, cancellationToken).ConfigureAwait(false);
                if (daemon is not null) return daemon;
                invocation.Warnings.Add("clamd did not start; scanned with clamscan instead (slower).");
            }
            return await ScanWithClamscanAsync(invocation, files, work, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            try
            {
                Directory.Delete(work, recursive: true);
            }
            catch (IOException)
            {
                // Temp files; harmless if they stay.
            }
        }
    }

    /// <summary>Single clamscan process: loads the database itself and scans one file at a time (~25 files/s).</summary>
    private async Task<IReadOnlyList<SecurityFinding>> ScanWithClamscanAsync(EngineInvocation invocation, string[] files, string work, CancellationToken cancellationToken)
    {
        var list = await WriteListAsync(Path.Combine(work, "files.txt"), files, cancellationToken).ConfigureAwait(false);
        List<string> args =
        [
            "--stdout", "--infected", "--no-summary",
            "--database=" + _databaseFolder(),
            "--file-list=" + list,
            "--max-filesize=100M", "--max-scansize=400M",
        ];
        var result = await RunToolAsync(invocation, args, cancellationToken).ConfigureAwait(false);
        return Collect(invocation, [result], files.Length);
    }

    /// <summary>
    /// A private clamd for this scan: listening on 127.0.0.1 at a free port, with the signatures loaded once, and one
    /// clamdscan client per CPU core (max 8) each scanning its share of the files — about ten times faster than clamscan.
    /// The daemon is stopped afterwards (its process job also ends it on cancel). Returns null when clamd does not come up.
    /// </summary>
    private async Task<IReadOnlyList<SecurityFinding>?> ScanWithDaemonAsync(EngineInvocation invocation, string clamd, string clamdscan,
        string[] files, string work, CancellationToken cancellationToken)
    {
        var clients = Math.Clamp(Environment.ProcessorCount, 2, 8);
        var config = Path.Combine(work, "clamd.conf");
        await File.WriteAllTextAsync(config, string.Join("\n",
            "TCPSocket " + FreeLoopbackPort(),
            "TCPAddr 127.0.0.1",
            "DatabaseDirectory " + _databaseFolder(),
            "MaxThreads " + clients,
            "Foreground yes",
            "MaxFileSize 100M",
            "MaxScanSize 400M",
            "SelfCheck 0",
            string.Empty), new UTF8Encoding(false), cancellationToken).ConfigureAwait(false);

        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var daemon = Runner.RunAsync(new ProcessRunRequest(clamd, ["--config-file=" + config], work, invocation.Request.Timeout + DaemonStartTimeout,
            1024 * 1024), stop.Token);
        try
        {
            if (!await WaitForDaemonAsync(clamdscan, config, work, daemon, cancellationToken).ConfigureAwait(false)) return null;

            var scans = new List<Task<ProcessRunResult>>();
            for (var i = 0; i < clients; i++)
            {
                var share = files.Where((_, index) => index % clients == i).ToArray();
                if (share.Length == 0) continue;
                var list = await WriteListAsync(Path.Combine(work, $"files{i}.txt"), share, cancellationToken).ConfigureAwait(false);
                scans.Add(Runner.RunAsync(new ProcessRunRequest(clamdscan,
                    ["--config-file=" + config, "--stdout", "--infected", "--no-summary", "--file-list=" + list],
                    work, invocation.Request.Timeout, DefaultMaxOutputBytes), cancellationToken));
            }
            var results = await Task.WhenAll(scans).ConfigureAwait(false);
            return Collect(invocation, results, files.Length);
        }
        finally
        {
            await stop.CancelAsync().ConfigureAwait(false);
            try
            {
                await daemon.ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // Expected: the daemon is stopped by cancelling its run (or never started, which was handled above).
            }
        }
    }

    private async Task<bool> WaitForDaemonAsync(string clamdscan, string config, string work, Task<ProcessRunResult> daemon, CancellationToken cancellationToken)
    {
        var deadline = Time.GetUtcNow() + DaemonStartTimeout;
        while (Time.GetUtcNow() < deadline)
        {
            if (daemon.IsCompleted) return false;   // clamd exited (bad config, port taken, database error)
            var ping = await Runner.RunAsync(new ProcessRunRequest(clamdscan, ["--config-file=" + config, "--ping", "1"], work,
                TimeSpan.FromSeconds(10), 64 * 1024), cancellationToken).ConfigureAwait(false);
            if (ping.ExitCode == 0) return true;
            await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken).ConfigureAwait(false);
        }
        return false;
    }

    /// <summary>Findings of every run; a timed-out run keeps what it found and is reported as incomplete.</summary>
    private List<SecurityFinding> Collect(EngineInvocation invocation, IReadOnlyList<ProcessRunResult> results, int fileCount)
    {
        var findings = new List<SecurityFinding>();
        var warnings = new List<string>();
        foreach (var result in results)
        {
            var (f, w) = Parse(result.StandardOutput, invocation.Request.RootFolder, Time.GetUtcNow());
            findings.AddRange(f);
            warnings.AddRange(w);
            // 0 = clean, 1 = something found, 2 = errors (some files may still have been scanned).
            if (!result.TimedOut && result.ExitCode is not (0 or 1) && f.Count == 0 && w.Count == 0)
                throw new EngineRunException("ClamAV failed (" + Describe(result) + ").");
        }
        if (results.Any(r => r.TimedOut))
        {
            if (findings.Count == 0 && results.All(r => r.TimedOut))
                throw new EngineRunException($"ClamAV timed out after {invocation.Request.Timeout.TotalMinutes:0} min ({fileCount:N0} files).");
            invocation.Warnings.Add($"ClamAV did not finish all {fileCount:N0} files within {invocation.Request.Timeout.TotalMinutes:0} min; results are incomplete.");
        }
        invocation.Warnings.AddRange(warnings.Distinct().Take(5));
        return findings;
    }

    private static async Task<string> WriteListAsync(string path, string[] files, CancellationToken cancellationToken)
    {
        // clamscan/clamdscan read the list as plain UTF-8: a byte-order mark would break the first path.
        await File.WriteAllLinesAsync(path, files, new UTF8Encoding(false), cancellationToken).ConfigureAwait(false);
        return path;
    }

    private static int FreeLoopbackPort()
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    /// <summary>Parses "path: Signature.Name FOUND" lines; other non-empty lines are reported as warnings.</summary>
    public static (IReadOnlyList<SecurityFinding> Findings, IReadOnlyList<string> Warnings) Parse(string output, string rootFolder, DateTimeOffset detectedAtUtc)
    {
        var findings = new List<SecurityFinding>();
        var warnings = new List<string>();
        foreach (var raw in (output ?? string.Empty).Split('\n'))
        {
            var line = raw.Trim().TrimStart('﻿');
            if (line.Length == 0) continue;
            var m = FoundLine().Match(line);
            if (!m.Success)
            {
                warnings.Add("ClamAV: " + line);
                continue;
            }
            var signature = m.Groups["sig"].Value;
            var path = EngineOutput.ToRelative(rootFolder, m.Groups["path"].Value);
            var (severity, confidence, category, kind) = Classify(signature);
            findings.Add(EngineOutput.Create(
                Id, "clamav." + signature,
                $"ClamAV: {signature}",
                $"ClamAV detected {kind} '{signature}' in this file.",
                category, severity, confidence,
                new SourceLocation(path, 0, 0),
                signature,
                [new Evidence("signature", "ClamAV signature", signature, "clamav")],
                [], [],
                "Do not run or deploy this file. Replace it (or the package it came from) with a clean copy from the original vendor, " +
                "or delete it, and check the rest of the package. Report false positives to Cisco Talos.",
                detectedAtUtc));
        }
        return (findings, warnings);
    }

    /// <summary>Potentially unwanted software and heuristics are less certain than named malware signatures.</summary>
    private static (Severity, Confidence, FindingCategory, string Kind) Classify(string signature) => signature switch
    {
        _ when signature.StartsWith("PUA.", StringComparison.OrdinalIgnoreCase) =>
            (Severity.Medium, Confidence.Medium, FindingCategory.SuspiciousPattern, "potentially unwanted software"),
        _ when signature.StartsWith("Heuristics.", StringComparison.OrdinalIgnoreCase) =>
            (Severity.Medium, Confidence.Medium, FindingCategory.SuspiciousPattern, "a heuristic match"),
        _ when signature.EndsWith(".UNOFFICIAL", StringComparison.OrdinalIgnoreCase) =>
            (Severity.High, Confidence.Medium, FindingCategory.Malware, "an unofficial (third-party) signature"),
        _ => (Severity.Critical, Confidence.High, FindingCategory.Malware, "malware"),
    };

    [GeneratedRegex(@"^(?<path>.+): (?<sig>\S+) FOUND$")]
    private static partial Regex FoundLine();
}
