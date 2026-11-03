using System.Globalization;
using WebGuard.Core.AI;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Scanning;
using WebGuard.Presentation.Formatting;
using WebGuard.Presentation.Mvvm;

namespace WebGuard.Presentation.ViewModels;

/// <summary>Visual intent used by XAML triggers for colour and icon selection.</summary>
public enum StatusTone { Neutral, Success, Warning, Danger, Info }

public sealed class FileItemViewModel
{
    public FileItemViewModel(FileInventoryItem item, string rootFolder)
    {
        ArgumentNullException.ThrowIfNull(item);
        Item = item;
        FullPath = Path.Combine(rootFolder, item.RelativePath);
    }

    public FileInventoryItem Item { get; }
    public string FullPath { get; }
    public string FileName => Item.FileName;
    public string RelativePath => Item.RelativePath;
    public string Directory => string.IsNullOrEmpty(Item.Directory) ? "(root)" : Item.Directory;
    public string Extension => string.IsNullOrEmpty(Item.Extension) ? "(no ext)" : Item.Extension.ToLowerInvariant();
    public long SizeBytes => Item.SizeBytes;
    public string SizeText => DisplayFormat.Bytes(Item.SizeBytes);
    public string SizeDetailText => $"{DisplayFormat.Bytes(Item.SizeBytes)} ({Item.SizeBytes.ToString("N0", CultureInfo.CurrentCulture)} bytes)";
    public string? Sha256 => Item.Sha256;
    public string ShortHash => Item.Sha256 is { Length: > 16 } h ? h[..16].ToUpperInvariant() + "…" : "—";
    public string FullHashDisplay => Item.Sha256?.ToUpperInvariant() ?? "Not computed";
    public bool HasHash => Item.Sha256 is not null;
    public string StatusText => DisplayFormat.Status(Item.Status);
    public FileScanStatus Status => Item.Status;
    public StatusTone Tone => Item.Status switch
    {
        FileScanStatus.Hashed => StatusTone.Success,
        FileScanStatus.Error => StatusTone.Danger,
        _ => StatusTone.Warning,
    };
    public string LastModifiedText => DisplayFormat.DateTime(Item.LastModifiedUtc);
    public string HashDurationText => Item.Status == FileScanStatus.Hashed
        ? Item.HashDurationMs.ToString("0.##", CultureInfo.CurrentCulture) + " ms"
        : "—";
    public string? Error => Item.Error;
    public string Notes => Item.Status switch
    {
        FileScanStatus.Hashed => "SHA-256 computed. Findings from the security engines for this file are listed on the Findings page.",
        FileScanStatus.SkippedSize => Item.Error ?? "File exceeds the configured hash limit.",
        FileScanStatus.SkippedLink => "Symbolic link or junction. Not followed so the scan cannot leave the selected folder.",
        _ => "The file could not be read: " + (Item.Error ?? "unknown error"),
    };
}

public sealed class FindingItemViewModel(SecurityFinding finding)
{
    public SecurityFinding Finding { get; } = finding;
    public string SeverityText => Finding.Severity.ToString();
    public Severity Severity => Finding.Severity;
    public string File => Path.GetFileName(Finding.Location.RelativePath);
    public string Location => Finding.Location.ToString();
    public string Title => Finding.Title;
    public string Description => Finding.Description;
    public string Engine => Finding.EngineId;
    public string RuleId => Finding.RuleId;
    public string StatusText => Finding.Status.ToString();
    public string CategoryText => Finding.Category switch
    {
        FindingCategory.VulnerableDependency => "Vulnerable dependency",
        FindingCategory.SuspiciousPattern => "Suspicious pattern",
        _ => Finding.Category.ToString(),
    };
    public string ConfidenceText => Finding.Confidence + " confidence";
    public bool IsAiHypothesis => Finding.Origin == FindingOrigin.AiHypothesis;

    /// <summary>Set by the CISA KEV enricher: the CVE is exploited in the wild.</summary>
    public bool IsKnownExploited => Finding.Evidence.Any(e => e.Kind == "known-exploited");
    public string? Remediation => Finding.Remediation;
    public bool HasRemediation => !string.IsNullOrWhiteSpace(Finding.Remediation);
    public IReadOnlyList<Evidence> Evidence => Finding.Evidence;
    public bool HasEvidence => Finding.Evidence.Count > 0;
    public string References => string.Join(", ", Finding.CweIds.Concat(Finding.AdvisoryIds));
    public bool HasReferences => Finding.CweIds.Count + Finding.AdvisoryIds.Count > 0;
    public string Fingerprint => Finding.Fingerprint;
}

/// <summary>Per-engine outcome of the last scan, shown on the Findings page.</summary>
public sealed class EngineRunViewModel(EngineRunSummary run)
{
    public string Name => run.DisplayName;
    public string Outcome => run.Outcome == nameof(EngineAvailability.NotInstalled) ? "Not installed" : run.Outcome;
    public string Message => run.Message ?? string.Empty;
    public string VersionText => run.Version is null ? string.Empty : "v" + run.Version;
    public int FindingCount => run.FindingCount;
    public StatusTone Tone => run.Outcome switch
    {
        "Completed" => StatusTone.Success,
        "Failed" or "Error" => StatusTone.Danger,
        "Planned" => StatusTone.Info,
        _ => StatusTone.Warning,
    };
}

/// <summary>Editable engine configuration row on the Settings page.</summary>
public sealed class EngineSettingViewModel(string id, string name, string executablePath, bool enabled) : ObservableObject
{
    private string _executablePath = executablePath;
    private bool _enabled = enabled;

    public string Id { get; } = id;
    public string Name { get; } = name;
    public string ExecutablePath { get => _executablePath; set => SetProperty(ref _executablePath, value?.Trim().Trim('"') ?? string.Empty); }
    public bool Enabled { get => _enabled; set => SetProperty(ref _enabled, value); }
}

public sealed class VulnerabilityRowViewModel(WebGuard.Core.Intelligence.VulnerabilityRecord record)
{
    public string Id => record.Id;
    public string Summary => record.Summary;
    public string SeverityText => record.Severity.ToString();
    public Severity Severity => record.Severity;
    public string Aliases => string.Join(", ", record.Aliases);
    public string FixedText => record.FixedVersions.Count == 0 ? "No fix published" : "Fixed in " + string.Join(", ", record.FixedVersions);
    public bool KnownExploited => record.KnownExploited;
    public string RetrievedText => $"{record.SourceId} · {DisplayFormat.DateTime(record.RetrievedAtUtc)}";
}

public sealed class EngineStatusViewModel : ObservableObject
{
    private string _availability = "Checking…";
    private string _message = string.Empty;
    private string? _version;
    private StatusTone _tone = StatusTone.Neutral;

    public EngineStatusViewModel(string id, string name, string category, string description, string phase, bool sendsDataExternally = false)
    {
        Id = id;
        Name = name;
        Category = category;
        Description = description;
        Phase = phase;
        SendsDataExternally = sendsDataExternally;
    }

    public string Id { get; }
    public string Name { get; }
    public string Category { get; }
    public string Description { get; }
    public string Phase { get; }
    public bool SendsDataExternally { get; }
    public string Availability { get => _availability; private set => SetProperty(ref _availability, value); }
    public string Message { get => _message; private set => SetProperty(ref _message, value); }
    public string? Version { get => _version; private set => SetProperty(ref _version, value); }
    public StatusTone Tone { get => _tone; private set => SetProperty(ref _tone, value); }

    public void Apply(EngineStatus status)
    {
        ArgumentNullException.ThrowIfNull(status);
        Availability = status.Availability switch
        {
            EngineAvailability.Planned => Phase,
            EngineAvailability.NotInstalled => "Not installed",
            EngineAvailability.Disabled => "Disabled",
            EngineAvailability.Ready => "Ready",
            _ => "Error",
        };
        Message = status.Message;
        Version = status.Version;
        Tone = status.Availability switch
        {
            EngineAvailability.Ready => StatusTone.Success,
            EngineAvailability.Planned => StatusTone.Info,
            EngineAvailability.Error => StatusTone.Danger,
            _ => StatusTone.Warning,
        };
    }

    public static EngineStatusViewModel From(SecurityEngineInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);
        return new(info.Id, info.DisplayName, info.Kind switch
        {
            EngineKind.StaticAnalysis => "SAST",
            EngineKind.SecretDetection => "Secrets",
            EngineKind.DependencyAudit => "Dependencies",
            EngineKind.MalwareSignature => "Malware signatures",
            _ => "Code analysis",
        }, info.Description, info.PlannedPhase);
    }
}

public sealed class McpToolViewModel(McpToolDescriptor tool)
{
    public string Name => tool.Name;
    public string Description => tool.Description;
    public string Access => tool.Access switch
    {
        McpToolAccess.ReadOnly => "Read-only",
        McpToolAccess.ExecutesAllowListedTool => "Runs allow-listed engine",
        McpToolAccess.NetworkLookup => "Network lookup",
        _ => "Writes knowledge",
    };
    public bool RequiresHumanApproval => tool.RequiresHumanApproval;
    public bool NeedsSecondBrain => McpToolCatalog.SecondBrainTools.Contains(tool.Name);
    public string Availability => NeedsSecondBrain ? "Phase 4" : RequiresHumanApproval ? "Needs --allow" : "Always on";
    public StatusTone Tone => NeedsSecondBrain ? StatusTone.Info : tool.Access == McpToolAccess.ReadOnly ? StatusTone.Success : StatusTone.Warning;
}

/// <summary>An AI explanation of one finding. Always shown as an unverified hypothesis.</summary>
public sealed class AiAnalysisViewModel(AiAnalysis analysis)
{
    public AiAnalysis Analysis { get; } = analysis;
    public string Summary => Analysis.Summary;
    public string WhyRisky => Analysis.WhyRisky;
    public bool HasWhyRisky => !string.IsNullOrWhiteSpace(Analysis.WhyRisky);
    public string? Remediation => Analysis.ProposedRemediation;
    public bool HasRemediation => !string.IsNullOrWhiteSpace(Analysis.ProposedRemediation);
    public string Footer => $"{Analysis.Model} · {Analysis.Confidence} confidence · {DisplayFormat.DateTime(Analysis.CreatedAtUtc)}";
}

/// <summary>Deterministic observation from the inventory. Not a finding: it only points to where the engines will look.</summary>
public sealed record InventoryInsight(string Title, string Detail, StatusTone Tone);

public sealed record LabeledValue(string Label, string Value);
