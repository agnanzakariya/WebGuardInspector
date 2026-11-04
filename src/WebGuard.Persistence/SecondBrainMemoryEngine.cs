using System.Diagnostics;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Knowledge;
using WebGuard.Core.Scanning;

namespace WebGuard.Persistence;

/// <summary>
/// Recognises files a person already confirmed as malicious: any inventoried file whose SHA-256 equals a file with a
/// Confirmed malware or suspicious-pattern finding in the Second Brain (in any project, at any path) is reported at
/// once, without a signature engine or an online lookup. Reads only the vault; sends nothing anywhere.
/// </summary>
public sealed class SecondBrainMemoryEngine(ObsidianSecondBrain brain, Func<bool> enabled, TimeProvider? timeProvider = null) : ISecurityEngine
{
    public const string Id = "second-brain";
    public const string RuleId = "known-confirmed-file";
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    public SecurityEngineInfo Info { get; } = new(
        Id, "Second Brain memory", EngineKind.MalwareSignature,
        "Flags files identical (SHA-256) to files you confirmed as malicious in earlier scans; no engine or online lookup needed.",
        "Phase 3", null);

    public async Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        if (!enabled()) return new EngineStatus(EngineAvailability.Disabled, null, null, "Turned off in Settings → Second Brain.");
        var status = await brain.GetStatusAsync(cancellationToken).ConfigureAwait(false);
        return status.Availability == EngineAvailability.Ready
            ? new EngineStatus(EngineAvailability.Ready, null, status.ExecutablePath, "Compares file hashes with verdicts in the vault.")
            : new EngineStatus(EngineAvailability.Disabled, null, null, "Needs a Second Brain vault (Settings → Second Brain).");
    }

    public async Task<EngineScanResult> ScanAsync(EngineScanRequest request, IProgress<EngineProgress>? progress, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var sw = Stopwatch.StartNew();
        var hashed = request.Files.Where(f => f is { Status: FileScanStatus.Hashed, Sha256: not null }).ToArray();
        progress?.Report(new EngineProgress(Id, $"Comparing {hashed.Length:N0} file hashes with the Second Brain…", null));
        IReadOnlyList<KnownFileFinding> known;
        try
        {
            known = await brain.GetKnownFindingsAsync(hashed.Select(f => f.Sha256!).ToArray(), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return new EngineScanResult(Id, false, [], sw.Elapsed, null, ex.Message);
        }

        var confirmed = known
            .Where(k => k.Status == ValidationStatus.Confirmed && k.Category is FindingCategory.Malware or FindingCategory.SuspiciousPattern)
            .ToLookup(k => k.Sha256, StringComparer.OrdinalIgnoreCase);
        var project = brain.ProjectNameFor(request.RootFolder);
        var now = _time.GetUtcNow();
        var findings = new List<SecurityFinding>();
        foreach (var file in hashed)
        {
            // In the same project and path the engine that found it reports it again (or its result is reused), so
            // only identical copies elsewhere are new information.
            var matches = confirmed[file.Sha256!]
                .Where(k => !(string.Equals(k.Project, project, StringComparison.OrdinalIgnoreCase) && SamePath(k.RelativePath, file.RelativePath)))
                .ToArray();
            if (matches.Length == 0) continue;
            var first = matches[0];
            var where = first.Project is null ? first.RelativePath : $"{first.RelativePath} in project {first.Project}";
            var verdicts = string.Join("; ", matches.Select(m => $"{m.Title} ({m.EngineId} / {m.RuleId})").Distinct().Take(5));
            findings.Add(new SecurityFinding(
                Guid.NewGuid(),
                FindingFingerprint.Compute(Id, RuleId, file.RelativePath, file.Sha256),
                Id,
                RuleId,
                "Identical to a file you confirmed as malicious",
                $"This file has the same SHA-256 as {where}, which a person confirmed in the Second Brain: {verdicts}. " +
                "It was recognised from that verdict without running a signature engine or an online lookup.",
                FindingCategory.Malware,
                matches.Max(m => m.Severity),
                Confidence.High,
                FindingOrigin.Engine,
                new SourceLocation(file.RelativePath, 0, 0),
                [new Evidence("sha256", "SHA-256 of the file", file.Sha256, Id)],
                [],
                [],
                "Remove the file (or restore it from a trusted source) as you did for the confirmed copy.",
                ValidationStatus.Confirmed,
                now));
        }
        return new EngineScanResult(Id, true, findings, sw.Elapsed, null, null);
    }

    private static bool SamePath(string a, string b) =>
        string.Equals(a.Replace('\\', '/').Trim('/'), b.Replace('\\', '/').Trim('/'), StringComparison.OrdinalIgnoreCase);
}
