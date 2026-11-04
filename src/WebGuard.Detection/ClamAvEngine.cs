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

    protected override string ReadyMessage(string executablePath) =>
        $"{executablePath} · {ClamAvDatabase.Inspect(_databaseFolder()).Describe()}";

    protected override async Task<IReadOnlyList<SecurityFinding>> RunAsync(EngineInvocation invocation, CancellationToken cancellationToken)
    {
        var root = invocation.Request.RootFolder;
        var files = invocation.Request.Files.Select(f => Path.Combine(root, f.RelativePath)).Where(File.Exists).ToArray();
        if (files.Length == 0) return [];

        // clamscan reads the list as plain UTF-8: a byte-order mark would break the first path.
        var list = Path.Combine(Path.GetTempPath(), $"webguard-clamav-{invocation.Request.ScanId:N}.txt");
        await File.WriteAllLinesAsync(list, files, new UTF8Encoding(false), cancellationToken).ConfigureAwait(false);
        try
        {
            List<string> args =
            [
                "--stdout", "--infected", "--no-summary",
                "--database=" + _databaseFolder(),
                "--file-list=" + list,
                "--max-filesize=100M", "--max-scansize=400M",
            ];
            var result = await RunToolAsync(invocation, args, cancellationToken).ConfigureAwait(false);
            EnsureComplete(result);
            // 0 = clean, 1 = something found, 2 = errors (some files may still have been scanned).
            var (findings, warnings) = Parse(result.StandardOutput, root, Time.GetUtcNow());
            invocation.Warnings.AddRange(warnings.Take(5));
            if (result.ExitCode is not (0 or 1) && findings.Count == 0)
                throw new EngineRunException("ClamAV failed (" + Describe(result) + ").");
            return findings;
        }
        finally
        {
            try
            {
                File.Delete(list);
            }
            catch (IOException)
            {
                // Temp file; harmless if it stays.
            }
        }
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
