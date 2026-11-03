using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using WebGuard.Core;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Scanning;

namespace WebGuard.Scanner;

/// <summary>
/// Read-only recursive inventory with streaming SHA-256, followed by the configured security engines.
/// Never follows reparse points (symlinks/junctions), so a scan cannot leave the selected root.
/// </summary>
public sealed class LocalFolderScanner : ILocalScanner
{
    private static readonly TimeSpan ProgressInterval = TimeSpan.FromMilliseconds(60);
    private readonly ISecurityEngine[] _engines;
    private readonly IFindingEnricher[] _enrichers;
    private readonly TimeProvider _time;

    public LocalFolderScanner(
        IEnumerable<ISecurityEngine>? engines = null,
        IEnumerable<IFindingEnricher>? enrichers = null,
        TimeProvider? timeProvider = null)
    {
        _engines = engines?.ToArray() ?? [];
        _enrichers = enrichers?.ToArray() ?? [];
        _time = timeProvider ?? TimeProvider.System;
    }

    public async Task<ScanReport> ScanAsync(
        string folder,
        ScanOptions options,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
            throw new DirectoryNotFoundException($"Folder not found: {folder}");

        options = options.Normalize();
        var root = Path.GetFullPath(folder);
        var started = _time.GetUtcNow();
        var excluded = new HashSet<string>(options.ExcludedDirectories, StringComparer.OrdinalIgnoreCase);

        progress?.Report(new ScanProgress(ScanPhase.Discovering, 0, 0, 0, 0, root));
        var discovery = await Task.Run(() => Discover(root, excluded, cancellationToken), cancellationToken).ConfigureAwait(false);

        var results = new ConcurrentBag<FileInventoryItem>(discovery.Errors);
        var totalBytes = discovery.Files.Sum(f => f.Length);
        long bytesDone = 0;
        var examined = 0;
        var lastReport = Stopwatch.StartNew();
        var gate = new object();

        void Report(string current, bool force)
        {
            if (progress is null) return;
            lock (gate)
            {
                if (!force && lastReport.Elapsed < ProgressInterval) return;
                lastReport.Restart();
            }
            progress.Report(new ScanProgress(ScanPhase.Hashing, Volatile.Read(ref examined), discovery.Files.Count,
                Interlocked.Read(ref bytesDone), totalBytes, current));
        }

        Report(string.Empty, force: true);

        await Parallel.ForEachAsync(
            discovery.Files,
            new ParallelOptions { MaxDegreeOfParallelism = options.MaxDegreeOfParallelism, CancellationToken = cancellationToken },
            async (file, ct) =>
            {
                var item = await InventoryFileAsync(root, file, options, ct).ConfigureAwait(false);
                results.Add(item);
                Interlocked.Add(ref bytesDone, file.Length);
                Interlocked.Increment(ref examined);
                Report(item.RelativePath, force: false);
            }).ConfigureAwait(false);

        var files = results
            .OrderBy(f => f.RelativePath, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var scanId = Guid.NewGuid();
        var (engines, findings) = await RunEnginesAsync(scanId, root, files, options, progress, cancellationToken).ConfigureAwait(false);
        var finished = _time.GetUtcNow();
        progress?.Report(new ScanProgress(ScanPhase.Completed, files.Length, files.Length, totalBytes, totalBytes, string.Empty));

        return new ScanReport(
            ScanReport.CurrentSchemaVersion,
            AppInfo.Version,
            scanId,
            root,
            Environment.MachineName,
            started,
            finished,
            options,
            ScanStatistics.From(files, discovery.ExcludedDirectoryCount),
            engines,
            files,
            findings);
    }

    /// <summary>
    /// Runs every Ready engine in sequence against the inventoried folder. An engine failure is recorded in its summary
    /// and never aborts the scan; only cancellation does. Findings outside the inventory (excluded folders, paths that
    /// escape the root) are dropped, and duplicates are merged by fingerprint.
    /// </summary>
    private async Task<(IReadOnlyList<EngineRunSummary> Engines, IReadOnlyList<SecurityFinding> Findings)> RunEnginesAsync(
        Guid scanId,
        string root,
        FileInventoryItem[] files,
        ScanOptions options,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken)
    {
        var summaries = new List<EngineRunSummary>(_engines.Length);
        var findings = new List<SecurityFinding>();
        if (_engines.Length == 0) return (summaries, findings);

        var inventory = new HashSet<string>(files.Where(f => f.Status != FileScanStatus.Error).Select(f => NormalizePath(f.RelativePath)),
            StringComparer.OrdinalIgnoreCase);
        var workRoot = Path.Combine(Path.GetTempPath(), "WebGuardInspector", scanId.ToString("N"));
        Directory.CreateDirectory(workRoot);
        try
        {
            for (var i = 0; i < _engines.Length; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var engine = _engines[i];
                var index = i;
                progress?.Report(new ScanProgress(ScanPhase.Analyzing, index, _engines.Length, 0, 0, engine.Info.DisplayName));

                var status = await engine.GetStatusAsync(cancellationToken).ConfigureAwait(false);
                if (status.Availability != EngineAvailability.Ready)
                {
                    summaries.Add(new EngineRunSummary(engine.Info.Id, engine.Info.DisplayName, status.Availability.ToString(),
                        status.Version, 0, status.Message));
                    continue;
                }

                var workDir = Path.Combine(workRoot, engine.Info.Id);
                Directory.CreateDirectory(workDir);
                var engineProgress = progress is null ? null : new EngineProgressAdapter(p =>
                    progress.Report(new ScanProgress(ScanPhase.Analyzing, index, _engines.Length, 0, 0, p.Message)));
                EngineScanResult result;
                try
                {
                    result = await engine.ScanAsync(new EngineScanRequest(scanId, root, files, workDir, options.EngineTimeout),
                        engineProgress, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
                {
                    result = new EngineScanResult(engine.Info.Id, false, [], TimeSpan.Zero, null, ex.Message);
                }

                var inScope = result.Findings.Where(f => IsInScope(f.Location.RelativePath, inventory)).ToList();
                var kept = inScope.DistinctBy(f => f.Fingerprint, StringComparer.Ordinal).ToList();
                findings.AddRange(kept);
                var dropped = result.Findings.Count - inScope.Count;
                var message = result.Succeeded
                    ? $"{kept.Count} finding(s) in {result.Duration.TotalSeconds:0.0} s" +
                      (dropped > 0 ? $"; {dropped} outside the inventory ignored" : string.Empty) +
                      (result.Error is null ? "." : ". Warning: " + result.Error)
                    : result.Error ?? "Engine failed.";
                summaries.Add(new EngineRunSummary(engine.Info.Id, engine.Info.DisplayName, result.Succeeded ? "Completed" : "Failed",
                    status.Version, kept.Count, message));
            }
        }
        finally
        {
            try { Directory.Delete(workRoot, recursive: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }

        IReadOnlyList<SecurityFinding> merged = findings
            .GroupBy(f => f.Fingerprint, StringComparer.Ordinal)
            .Select(g => g.First())
            .ToArray();
        merged = await EnrichAsync(merged, summaries, cancellationToken).ConfigureAwait(false);

        var ordered = merged
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Location.RelativePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(f => f.Location.StartLine)
            .ToArray();
        return (summaries, ordered);
    }

    /// <summary>Applies each Ready enricher in turn; like engines, a failing enricher is recorded and skipped.</summary>
    private async Task<IReadOnlyList<SecurityFinding>> EnrichAsync(
        IReadOnlyList<SecurityFinding> findings,
        List<EngineRunSummary> summaries,
        CancellationToken cancellationToken)
    {
        foreach (var enricher in _enrichers)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var status = await enricher.GetStatusAsync(cancellationToken).ConfigureAwait(false);
            if (status.Availability != EngineAvailability.Ready)
            {
                summaries.Add(new EngineRunSummary(enricher.Info.Id, enricher.Info.DisplayName, status.Availability.ToString(),
                    status.Version, 0, status.Message));
                continue;
            }

            try
            {
                var result = await enricher.EnrichAsync(findings, cancellationToken).ConfigureAwait(false);
                // An enricher may annotate findings but never add, drop or re-identify them.
                if (result.Findings.Count != findings.Count ||
                    !result.Findings.Select(f => f.Fingerprint).SequenceEqual(findings.Select(f => f.Fingerprint), StringComparer.Ordinal))
                    throw new InvalidOperationException("Enricher changed the set of findings.");
                findings = result.Findings;
                summaries.Add(new EngineRunSummary(enricher.Info.Id, enricher.Info.DisplayName, "Completed", status.Version,
                    result.ChangedCount, result.Message));
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                summaries.Add(new EngineRunSummary(enricher.Info.Id, enricher.Info.DisplayName, "Failed", status.Version, 0, ex.Message));
            }
        }
        return findings;
    }

    private static string NormalizePath(string path) => path.Replace('\\', '/').Trim('/');

    private static bool IsInScope(string relativePath, HashSet<string> inventory)
    {
        if (string.IsNullOrEmpty(relativePath) || Path.IsPathRooted(relativePath)) return false;
        var normalized = NormalizePath(relativePath);
        return !normalized.StartsWith("../", StringComparison.Ordinal) && normalized != ".." && inventory.Contains(normalized);
    }

    private static DiscoveryResult Discover(string root, HashSet<string> excluded, CancellationToken cancellationToken)
    {
        var files = new List<FileInfo>();
        var errors = new List<FileInventoryItem>();
        var excludedCount = 0;
        var pending = new Stack<DirectoryInfo>();
        pending.Push(new DirectoryInfo(root));

        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = pending.Pop();
            try
            {
                foreach (var entry in current.EnumerateFileSystemInfos())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (entry is DirectoryInfo dir)
                    {
                        if (excluded.Contains(dir.Name) || dir.Attributes.HasFlag(FileAttributes.ReparsePoint))
                        {
                            excludedCount++;
                            continue;
                        }
                        pending.Push(dir);
                    }
                    else if (entry is FileInfo file)
                    {
                        files.Add(file);
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                errors.Add(new FileInventoryItem(Path.GetRelativePath(root, current.FullName), string.Empty, 0, null, null,
                    FileScanStatus.Error, 0, ex.Message));
            }
        }

        return new DiscoveryResult(files, errors, excludedCount);
    }

    private static async Task<FileInventoryItem> InventoryFileAsync(string root, FileInfo file, ScanOptions options, CancellationToken cancellationToken)
    {
        var relative = Path.GetRelativePath(root, file.FullName);
        var extension = file.Extension;
        try
        {
            var modified = new DateTimeOffset(file.LastWriteTimeUtc, TimeSpan.Zero);
            if (file.Attributes.HasFlag(FileAttributes.ReparsePoint))
                return new FileInventoryItem(relative, extension, file.Length, modified, null, FileScanStatus.SkippedLink, 0, null);
            if (file.Length > options.MaxHashBytes)
                return new FileInventoryItem(relative, extension, file.Length, modified, null, FileScanStatus.SkippedSize, 0,
                    $"Exceeds hash limit of {options.MaxHashBytes:N0} bytes");

            var sw = Stopwatch.StartNew();
            var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                81920, FileOptions.Asynchronous | FileOptions.SequentialScan);
            await using (stream.ConfigureAwait(false))
            {
                var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
                sw.Stop();
                return new FileInventoryItem(relative, extension, file.Length, modified, Convert.ToHexStringLower(hash),
                    FileScanStatus.Hashed, Math.Round(sw.Elapsed.TotalMilliseconds, 2), null);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return new FileInventoryItem(relative, extension, 0, null, null, FileScanStatus.Error, 0, ex.Message);
        }
    }

    private sealed record DiscoveryResult(List<FileInfo> Files, List<FileInventoryItem> Errors, int ExcludedDirectoryCount);

    private sealed class EngineProgressAdapter(Action<EngineProgress> handler) : IProgress<EngineProgress>
    {
        public void Report(EngineProgress value) => handler(value);
    }
}
