using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows.Input;
using WebGuard.Core.AI;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Intelligence;
using WebGuard.Core.Knowledge;
using WebGuard.Core.Scanning;
using WebGuard.Presentation.Formatting;
using WebGuard.Presentation.Mvvm;
using WebGuard.Presentation.Services;

namespace WebGuard.Presentation.ViewModels;

public enum PageKey { Overview, LocalScanner, Findings, Fixing, AiAnalyst, SecondBrain, Intelligence, ScanHistory, Settings }

public abstract class PageViewModel : ObservableObject
{
    public abstract PageKey Key { get; }
    public abstract string Title { get; }
    public abstract string Subtitle { get; }
}

/// <summary>Engine statuses shared by Overview, Findings and Settings.</summary>
public sealed class EngineCatalogViewModel : ObservableObject
{
    private readonly ISecurityEngine[] _engines;

    public EngineCatalogViewModel(IEnumerable<ISecurityEngine> engines)
    {
        _engines = engines.ToArray();
        Engines = new ObservableCollection<EngineStatusViewModel>(_engines.Select(e => EngineStatusViewModel.From(e.Info)));
    }

    public ObservableCollection<EngineStatusViewModel> Engines { get; }

    public int ReadyCount => Engines.Count(e => e.Tone == StatusTone.Success);

    public string Summary => ReadyCount == 0
        ? "No engines ready · install tools or set paths in Settings"
        : $"{ReadyCount} of {Engines.Count} engines ready";

    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        for (var i = 0; i < _engines.Length; i++)
        {
            Engines[i].Apply(await _engines[i].GetStatusAsync(cancellationToken).ConfigureAwait(true));
        }
        OnPropertyChanged(nameof(ReadyCount));
        OnPropertyChanged(nameof(Summary));
    }
}

public sealed class FindingsViewModel : PageViewModel, IDisposable
{
    private SeveritySummary _summary = SeveritySummary.Empty;
    private FindingItemViewModel? _selected;
    private string _searchText = string.Empty;
    private IReadOnlyList<SecurityFinding> _all = [];
    private ScanReport? _report;
    private readonly IAiSecurityAnalyst? _analyst;
    private readonly ISecondBrainRepository? _secondBrain;
    private readonly SettingsService? _settings;
    private readonly IExternalLauncher? _launcher;
    private string _validationMessage = string.Empty;
    private bool _syncingStatus;
    private readonly Dictionary<Guid, AiAnalysisViewModel> _analyses = [];
    private CancellationTokenSource? _analysisCts;
    private bool _isAnalyzing;
    private string _analysisMessage = string.Empty;

    public FindingsViewModel(EngineCatalogViewModel engines, IAiSecurityAnalyst? analyst = null, ISecondBrainRepository? secondBrain = null,
        SettingsService? settings = null, IExternalLauncher? launcher = null)
    {
        EngineCatalog = engines;
        _analyst = analyst;
        _secondBrain = secondBrain;
        _settings = settings;
        _launcher = launcher;
        OpenNoteCommand = new RelayCommand(OpenNote, () => SelectedFinding is not null && _secondBrain?.GetFindingNoteUri(SelectedFinding.Finding.Fingerprint) is not null);
        AnalyzeCommand = new AsyncRelayCommand(AnalyzeSelectedAsync, () => _analyst is not null && SelectedFinding is not null && !IsAnalyzing,
            ex => AnalysisMessage = "AI analysis failed: " + ex.Message);
        CancelAnalysisCommand = new RelayCommand(() => _analysisCts?.Cancel(), () => IsAnalyzing);
    }

    public AsyncRelayCommand AnalyzeCommand { get; }
    public ICommand OpenNoteCommand { get; }
    public bool HasSecondBrain => _secondBrain is not null;
    public string ValidationMessage { get => _validationMessage; private set => SetProperty(ref _validationMessage, value); }

    /// <summary>Verdicts a person can give; stored in the finding's Second Brain note and reused on later scans.</summary>
    public IReadOnlyList<ValidationStatus> Statuses { get; } = Enum.GetValues<ValidationStatus>();

    public ValidationStatus? SelectedStatus
    {
        get => SelectedFinding?.Finding.Status;
        set
        {
            if (_syncingStatus || value is not { } status || SelectedFinding is null || status == SelectedFinding.Finding.Status) return;
            _ = SetStatusAsync(SelectedFinding.Finding, status);
        }
    }

    /// <summary>Raised after a scan is loaded.</summary>
    public event EventHandler<ScanReport>? ReportLoaded;

    /// <summary>Raised after a verdict is recorded, with the updated finding.</summary>
    public event EventHandler<SecurityFinding>? StatusRecorded;

    /// <summary>The loaded scan, or null before the first scan.</summary>
    public ScanReport? Report => _report;

    /// <summary>All findings of the loaded scan with their current verdicts.</summary>
    public IReadOnlyList<SecurityFinding> AllFindings => _all;

    /// <summary>Records a verdict in the Second Brain and shows it on the finding. Returns false when it could not be recorded.</summary>
    internal async Task<bool> SetStatusAsync(SecurityFinding finding, ValidationStatus status, string? note = null)
    {
        if (_secondBrain is null)
        {
            ValidationMessage = "Set a Second Brain vault in Settings to record verdicts.";
            return false;
        }
        try
        {
            await _secondBrain.RecordValidationAsync(
                new ValidationRecord(finding.Fingerprint, status, Environment.UserName, note, DateTimeOffset.UtcNow), CancellationToken.None).ConfigureAwait(true);
            _all = _all.Select(f => f.Fingerprint == finding.Fingerprint ? f with { Status = status } : f).ToArray();
            Rebuild(finding.Fingerprint);
            ValidationMessage = $"Marked {status} in the Second Brain.";
            StatusRecorded?.Invoke(this, finding with { Status = status });
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            ValidationMessage = "Could not record the verdict: " + ex.Message;
            OnPropertyChanged(nameof(SelectedStatus));
            return false;
        }
    }

    private void OpenNote()
    {
        if (SelectedFinding is not null && _secondBrain?.GetFindingNoteUri(SelectedFinding.Finding.Fingerprint) is { } uri) _launcher?.Open(uri);
    }
    public ICommand CancelAnalysisCommand { get; }
    public bool HasAnalyst => _analyst is not null;

    public bool IsAnalyzing
    {
        get => _isAnalyzing;
        private set
        {
            if (!SetProperty(ref _isAnalyzing, value)) return;
            AnalyzeCommand.RaiseCanExecuteChanged();
            (CancelAnalysisCommand as IRaiseCanExecuteChanged)?.RaiseCanExecuteChanged();
        }
    }

    public string AnalysisMessage { get => _analysisMessage; private set => SetProperty(ref _analysisMessage, value); }

    /// <summary>Analysis of the selected finding, kept per finding while the scan is loaded.</summary>
    public AiAnalysisViewModel? CurrentAnalysis =>
        SelectedFinding is not null && _analyses.TryGetValue(SelectedFinding.Finding.Id, out var a) ? a : null;

    public bool HasCurrentAnalysis => CurrentAnalysis is not null;

    private async Task<string> RememberAnalysisAsync(SecurityFinding finding, AiAnalysis analysis)
    {
        if (_secondBrain is null || _settings?.Current.SecondBrainAutoRecord != true) return string.Empty;
        try
        {
            if ((await _secondBrain.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).Availability != EngineAvailability.Ready) return string.Empty;
            await _secondBrain.SaveAnalysisAsync(finding, analysis, CancellationToken.None).ConfigureAwait(true);
            return "Saved to the Second Brain.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return "Analysis not saved to the Second Brain: " + ex.Message;
        }
    }

    /// <summary>Cancels a running analysis (called when the main window closes).</summary>
    public void Dispose()
    {
        _analysisCts?.Cancel();
        _analysisCts?.Dispose();
        _analysisCts = null;
    }

    internal async Task AnalyzeSelectedAsync()
    {
        if (_analyst is null || _report is null || SelectedFinding is null || IsAnalyzing) return;
        var finding = SelectedFinding.Finding;
        _analysisCts = new CancellationTokenSource();
        IsAnalyzing = true;
        AnalysisMessage = "Analyzing with the local model… this can take a minute on CPU.";
        try
        {
            var context = FindingContextBuilder.Build(new ProjectScope(_report.RootFolder), finding, _all);
            var analysis = await _analyst.AnalyzeAsync(context, _analysisCts.Token).ConfigureAwait(true);
            _analyses[finding.Id] = new AiAnalysisViewModel(analysis);
            AnalysisMessage = await RememberAnalysisAsync(finding, analysis).ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            AnalysisMessage = "AI analysis canceled.";
        }
        catch (Exception ex) when (ex is InvalidOperationException or HttpRequestException or IOException or System.Text.Json.JsonException)
        {
            AnalysisMessage = "AI analysis failed: " + ex.Message;
        }
        finally
        {
            _analysisCts?.Dispose();
            _analysisCts = null;
            IsAnalyzing = false;
            OnPropertyChanged(nameof(CurrentAnalysis));
            OnPropertyChanged(nameof(HasCurrentAnalysis));
        }
    }

    public override PageKey Key => PageKey.Findings;
    public override string Title => "Findings";
    public override string Subtitle => "Risks, evidence and remediation";

    public EngineCatalogViewModel EngineCatalog { get; }
    public ObservableCollection<FindingItemViewModel> Findings { get; } = [];
    public ObservableCollection<EngineRunViewModel> EngineRuns { get; } = [];
    public bool HasEngineRuns => EngineRuns.Count > 0;
    public SeveritySummary Summary { get => _summary; private set => SetProperty(ref _summary, value); }
    public bool HasFindings => Findings.Count > 0;
    public bool HasNoFindings => Findings.Count == 0;
    public int TotalCount => _all.Count;
    public string TotalText => DisplayFormat.Count(_all.Count);
    public string SeverityCaption => $"{Summary.Critical} Critical, {Summary.High} High, {Summary.Medium} Medium, {Summary.Low} Low";

    public FindingItemViewModel? SelectedFinding
    {
        get => _selected;
        set
        {
            if (!SetProperty(ref _selected, value)) return;
            OnPropertyChanged(nameof(HasSelectedFinding));
            _syncingStatus = true;
            OnPropertyChanged(nameof(SelectedStatus));
            _syncingStatus = false;
            ValidationMessage = string.Empty;
            (OpenNoteCommand as IRaiseCanExecuteChanged)?.RaiseCanExecuteChanged();
            OnPropertyChanged(nameof(CurrentAnalysis));
            OnPropertyChanged(nameof(HasCurrentAnalysis));
            if (!IsAnalyzing) AnalysisMessage = string.Empty;
            AnalyzeCommand.RaiseCanExecuteChanged();
        }
    }

    public bool HasSelectedFinding => SelectedFinding is not null;

    public string SearchText
    {
        get => _searchText;
        set { if (SetProperty(ref _searchText, value ?? string.Empty)) Rebuild(); }
    }

    private bool AnyEngineCompleted => _report?.Engines.Any(e => e.Outcome == "Completed") == true;

    public string EmptyTitle => _report is null ? "No scan yet" : AnyEngineCompleted ? "No findings" : "No security engine ran";

    public string EmptyMessage => _report is null
        ? "Run a scan. Semgrep (SAST), Gitleaks (secrets), OSV-Scanner (dependencies), YARA-X (signatures) and the " +
          "MalwareBazaar hash lookup report here with severity, evidence and remediation."
        : AnyEngineCompleted
            ? "The engines that ran found nothing in the inventoried files. Engines that did not run are listed below with the reason."
            : "Install at least one engine (or set its executable path in Settings) and scan again. The status of each engine is listed below.";

    public void Load(ScanReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        _report = report;
        _all = report.Findings;
        _analyses.Clear();
        Summary = SeveritySummary.From(_all);
        EngineRuns.Clear();
        foreach (var run in report.Engines) EngineRuns.Add(new EngineRunViewModel(run));
        OnPropertyChanged(nameof(HasEngineRuns));
        OnPropertyChanged(nameof(EmptyTitle));
        OnPropertyChanged(nameof(EmptyMessage));
        Rebuild();
        ReportLoaded?.Invoke(this, report);
    }

    private void Rebuild(string? keepFingerprint = null)
    {
        keepFingerprint ??= SelectedFinding?.Finding.Fingerprint;
        Findings.Clear();
        var term = SearchText.Trim();
        foreach (var f in _all
                     .Where(f => term.Length == 0 ||
                                 f.Title.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                                 f.RuleId.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                                 f.EngineId.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                                 f.Location.RelativePath.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                                 f.AdvisoryIds.Any(a => a.Contains(term, StringComparison.OrdinalIgnoreCase)))
                     .OrderByDescending(f => f.Severity))
        {
            Findings.Add(new FindingItemViewModel(f));
        }
        SelectedFinding = Findings.FirstOrDefault(f => f.Finding.Fingerprint == keepFingerprint) ?? Findings.FirstOrDefault();
        foreach (var n in new[] { nameof(HasFindings), nameof(HasNoFindings), nameof(TotalCount), nameof(TotalText), nameof(SeverityCaption) })
            OnPropertyChanged(n);
    }
}

public sealed class OverviewViewModel(ScanWorkspaceViewModel workspace, FindingsViewModel findings, EngineCatalogViewModel engines) : PageViewModel
{
    public override PageKey Key => PageKey.Overview;
    public override string Title => "Overview";
    public override string Subtitle => "Security status of the selected local folder";
    public ScanWorkspaceViewModel Workspace { get; } = workspace;
    public FindingsViewModel Findings { get; } = findings;
    public EngineCatalogViewModel EngineCatalog { get; } = engines;
}

public sealed class LocalScannerViewModel(ScanWorkspaceViewModel workspace, SettingsService settings) : PageViewModel
{
    public override PageKey Key => PageKey.LocalScanner;
    public override string Title => "Local Scanner";
    public override string Subtitle => "Folder, progress and file inventory";
    public ScanWorkspaceViewModel Workspace { get; } = workspace;
    public IReadOnlyList<string> StatusFilters => ScanWorkspaceViewModel.StatusFilters;

    public string ScanPolicySummary
    {
        get
        {
            var s = settings.Current;
            return $"Read-only · {s.ExcludedDirectories.Count} excluded folder names · hash limit {s.MaxHashMegabytes} MB · " +
                   $"{s.MaxDegreeOfParallelism} parallel reader(s) · links not followed";
        }
    }

    public void RefreshPolicy() => OnPropertyChanged(nameof(ScanPolicySummary));
}

public sealed class AiAnalystViewModel : PageViewModel
{
    private readonly IAiSecurityAnalyst _analyst;
    private readonly IMcpServerHost _mcp;
    private readonly ScanWorkspaceViewModel? _workspace;
    private readonly IClipboardService? _clipboard;
    private string _copyMessage = string.Empty;

    public AiAnalystViewModel(IAiSecurityAnalyst analyst, IMcpServerHost mcp, ScanWorkspaceViewModel? workspace = null, IClipboardService? clipboard = null)
    {
        _analyst = analyst;
        _mcp = mcp;
        _workspace = workspace;
        _clipboard = clipboard;
        AnalystStatus = new EngineStatusViewModel("ai", analyst.DisplayName, "Local AI",
            "Explains why a finding is risky and drafts a fix you review. Open a finding and press Analyze with AI.", "Phase 3");
        McpStatus = new EngineStatusViewModel("mcp", "MCP Server (stdio, local)", "Tool interface",
            "Least-privilege tools scoped to one folder, with audit log; risky tools only with explicit --allow.", "Phase 3");
        Tools = mcp.Tools.Select(t => new McpToolViewModel(t)).ToArray();
        ApprovableTools = McpToolCatalog.ApprovableTools.Select(t => new ToolApprovalViewModel(t, OnApprovalChanged)).ToArray();
        CopyConfigCommand = new RelayCommand(() => Copy(ClientConfigJson, "MCP client config copied."), () => HasClientSetup);
        CopyClaudeCommand = new RelayCommand(() => Copy(ClaudeCodeCommand, "Claude Code command copied."), () => HasClientSetup);
        if (workspace is not null)
        {
            workspace.PropertyChanged += (_, e) =>
            {
                if (e.PropertyName is nameof(ScanWorkspaceViewModel.FolderPath) or nameof(ScanWorkspaceViewModel.IsFolderValid)) RaiseSetupChanged();
            };
        }
    }

    public override PageKey Key => PageKey.AiAnalyst;
    public override string Title => "AI Analyst";
    public override string Subtitle => "Local model analysis and MCP tools";
    public EngineStatusViewModel AnalystStatus { get; }
    public EngineStatusViewModel McpStatus { get; }
    public IReadOnlyList<McpToolViewModel> Tools { get; }
    public IReadOnlyList<ToolApprovalViewModel> ApprovableTools { get; }
    public ICommand CopyConfigCommand { get; }
    public ICommand CopyClaudeCommand { get; }
    public string CopyMessage { get => _copyMessage; private set => SetProperty(ref _copyMessage, value); }

    private McpClientSetup? Setup => _workspace is { IsFolderValid: true } w
        ? _mcp.GetClientSetup(w.FolderPath, ApprovableTools.Where(t => t.IsApproved).Select(t => t.Name).ToArray())
        : null;

    public bool HasClientSetup => Setup is { ExecutablePath.Length: > 0 };
    public string ClientConfigJson => Setup?.ConfigJson ?? "Select a project folder first; the server is limited to that folder.";
    public string ClaudeCodeCommand => Setup?.ClaudeCodeCommand ?? string.Empty;

    public IReadOnlyList<string> Guardrails { get; } =
    [
        "AI output is a hypothesis until a person validates it; it is never the sole basis for a malicious/safe verdict.",
        "Secrets are redacted before any context reaches the model; scanned code is treated as untrusted data.",
        "Only local AI endpoints (localhost) are accepted. Nothing is sent to a cloud model.",
        "Patches are proposed, never applied. The MCP server cannot modify files and logs every call.",
    ];

    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        AnalystStatus.Apply(await _analyst.GetStatusAsync(cancellationToken).ConfigureAwait(true));
        McpStatus.Apply(await _mcp.GetStatusAsync(cancellationToken).ConfigureAwait(true));
        RaiseSetupChanged();
    }

    private void OnApprovalChanged() => RaiseSetupChanged();

    private void RaiseSetupChanged()
    {
        OnPropertyChanged(nameof(HasClientSetup));
        OnPropertyChanged(nameof(ClientConfigJson));
        OnPropertyChanged(nameof(ClaudeCodeCommand));
        (CopyConfigCommand as IRaiseCanExecuteChanged)?.RaiseCanExecuteChanged();
        (CopyClaudeCommand as IRaiseCanExecuteChanged)?.RaiseCanExecuteChanged();
    }

    private void Copy(string text, string message)
    {
        if (_clipboard is null || string.IsNullOrEmpty(text)) return;
        _clipboard.SetText(text);
        CopyMessage = message;
    }
}

/// <summary>Pre-approval of one gated MCP tool for the generated client configuration.</summary>
public sealed class ToolApprovalViewModel(string name, Action changed) : ObservableObject
{
    private bool _isApproved;

    public string Name { get; } = name;

    public bool IsApproved
    {
        get => _isApproved;
        set { if (SetProperty(ref _isApproved, value)) changed(); }
    }
}

public sealed class SecondBrainViewModel : PageViewModel
{
    private readonly ISecondBrainRepository _repository;
    private readonly IExternalLauncher? _launcher;
    private string _query = string.Empty;
    private string _searchResult = string.Empty;
    private string _statsText = string.Empty;

    public SecondBrainViewModel(ISecondBrainRepository repository, IExternalLauncher? launcher = null)
    {
        _repository = repository;
        _launcher = launcher;
        Status = new EngineStatusViewModel("secondbrain", "Obsidian vault", "Knowledge base",
            "Every scan (clean or not), finding, AI analysis and verdict, kept as linked Markdown notes.", "Phase 4");
        SearchCommand = new AsyncRelayCommand(SearchAsync, () => Query.Trim().Length > 0, ex => SearchResult = "Search failed: " + ex.Message);
        OpenVaultCommand = new RelayCommand(() => Open(null), () => _repository.GetNoteUri(null) is not null);
        OpenDashboardCommand = new RelayCommand(() => Open("Dashboard.md"), () => _repository.GetNoteUri(null) is not null);
    }

    public override PageKey Key => PageKey.SecondBrain;
    public override string Title => "Second Brain";
    public override string Subtitle => "Every scan, finding and verdict in your Obsidian vault";
    public EngineStatusViewModel Status { get; }
    public AsyncRelayCommand SearchCommand { get; }
    public ICommand OpenVaultCommand { get; }
    public ICommand OpenDashboardCommand { get; }
    public ObservableCollection<KnowledgeHitViewModel> Results { get; } = [];
    public bool HasResults => Results.Count > 0;
    public string StatsText { get => _statsText; private set => SetProperty(ref _statsText, value); }

    public string Query
    {
        get => _query;
        set { if (SetProperty(ref _query, value ?? string.Empty)) SearchCommand.RaiseCanExecuteChanged(); }
    }

    public string SearchResult { get => _searchResult; private set => SetProperty(ref _searchResult, value); }

    public IReadOnlyList<string> Lifecycle { get; } = ["Detect", "Correlate", "Analyze", "Validate", "Remember", "Reuse"];

    public IReadOnlyList<LabeledValue> Entities { get; } =
    [
        new("Dashboard.md", "Projects, open Critical/High findings and recent scans"),
        new("Projects/", "One note per scanned folder: scan history and current findings"),
        new("Scans/", "One note per scan — clean scans included — with engines, results and inventory"),
        new("Findings/", "One note per unique finding: evidence, occurrences, AI analyses, validation history"),
        new("Rules/", "What each rule has found; add your team's fix guidance here"),
        new("My notes", "Each note ends with a section WebGuard never touches"),
    ];

    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        Status.Apply(await _repository.GetStatusAsync(cancellationToken).ConfigureAwait(true));
        var stats = await _repository.GetStatisticsAsync(cancellationToken).ConfigureAwait(true);
        StatsText = $"{stats.Projects} projects · {stats.Scans} scans · {stats.Findings} findings · {stats.Validated} validated";
        (OpenVaultCommand as IRaiseCanExecuteChanged)?.RaiseCanExecuteChanged();
        (OpenDashboardCommand as IRaiseCanExecuteChanged)?.RaiseCanExecuteChanged();
    }

    internal async Task SearchAsync()
    {
        SearchResult = "Searching…";
        Results.Clear();
        var hits = await _repository.SearchSimilarAsync(Query.Trim(), 15, CancellationToken.None).ConfigureAwait(true);
        foreach (var hit in hits) Results.Add(new KnowledgeHitViewModel(hit, () => Open(hit.NotePath)));
        SearchResult = hits.Count == 0
            ? "No matching knowledge yet. Findings are added automatically after each scan."
            : $"{hits.Count} matching finding(s), best first.";
        OnPropertyChanged(nameof(HasResults));
    }

    private void Open(string? notePath)
    {
        if (_repository.GetNoteUri(notePath) is { } uri) _launcher?.Open(uri);
    }
}

/// <summary>One search hit on the Second Brain page.</summary>
public sealed class KnowledgeHitViewModel(KnowledgeSearchHit hit, Action open)
{
    public string Title => hit.Title;
    public Severity Severity => hit.Severity;
    public string SeverityText => hit.Severity.ToString();
    public string Details => $"{hit.Status}{(hit.Project is null ? string.Empty : " · " + hit.Project)} · match {hit.Similarity:0.00}";
    public string Snippet => hit.Snippet;
    public ICommand OpenCommand { get; } = new RelayCommand(open);
}

public sealed class IntelligenceViewModel : PageViewModel
{
    private readonly IVulnerabilityIntelligence _vulnerabilities;
    private readonly IMalwareHashIntelligence[] _malware;
    private string _ecosystem = "npm";
    private string _packageName = string.Empty;
    private string _packageVersion = string.Empty;
    private string _lookupMessage = string.Empty;

    public IntelligenceViewModel(IVulnerabilityIntelligence vulnerabilities, IEnumerable<IMalwareHashIntelligence> malware)
    {
        _vulnerabilities = vulnerabilities;
        _malware = malware.ToArray();
        Sources = [Create(vulnerabilities.Source), .. _malware.Select(m => Create(m.Source))];
        LookupCommand = new AsyncRelayCommand(LookupAsync,
            () => PackageName.Trim().Length > 0 && PackageVersion.Trim().Length > 0,
            ex => LookupMessage = "Lookup failed: " + ex.Message);
    }

    public override PageKey Key => PageKey.Intelligence;
    public override string Title => "Intelligence";
    public override string Subtitle => "CVE, advisories and IOC cache";
    public IReadOnlyList<EngineStatusViewModel> Sources { get; }
    public AsyncRelayCommand LookupCommand { get; }
    public ObservableCollection<VulnerabilityRowViewModel> Results { get; } = [];
    public bool HasResults => Results.Count > 0;

    /// <summary>OSV ecosystem names (case-sensitive in the OSV API).</summary>
    public IReadOnlyList<string> Ecosystems { get; } = ["npm", "PyPI", "NuGet", "Maven", "Go", "crates.io", "RubyGems", "Packagist", "Pub"];

    public string Ecosystem { get => _ecosystem; set => SetProperty(ref _ecosystem, value ?? "npm"); }

    public string PackageName
    {
        get => _packageName;
        set { if (SetProperty(ref _packageName, value ?? string.Empty)) LookupCommand.RaiseCanExecuteChanged(); }
    }

    public string PackageVersion
    {
        get => _packageVersion;
        set { if (SetProperty(ref _packageVersion, value ?? string.Empty)) LookupCommand.RaiseCanExecuteChanged(); }
    }

    public string LookupMessage { get => _lookupMessage; private set => SetProperty(ref _lookupMessage, value); }

    public IReadOnlyList<string> PrivacyRules { get; } =
    [
        "Only package coordinates (name, version, ecosystem) or SHA-256 values are ever sent — never source code or credentials.",
        "External lookups are opt-in and can be disabled in Settings.",
        "Every result is cached locally with its source and retrieval time for offline reuse and audit.",
    ];

    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        Sources[0].Apply(await _vulnerabilities.GetStatusAsync(cancellationToken).ConfigureAwait(true));
        for (var i = 0; i < _malware.Length; i++)
            Sources[i + 1].Apply(await _malware[i].GetStatusAsync(cancellationToken).ConfigureAwait(true));
    }

    internal async Task LookupAsync()
    {
        var coordinate = new PackageCoordinate(Ecosystem, PackageName.Trim(), PackageVersion.Trim());
        LookupMessage = $"Looking up {coordinate.Ecosystem}/{coordinate.Name}@{coordinate.Version}…";
        Results.Clear();
        OnPropertyChanged(nameof(HasResults));
        try
        {
            var records = await _vulnerabilities.LookupAsync(coordinate, CancellationToken.None).ConfigureAwait(true);
            foreach (var r in records.OrderByDescending(r => r.KnownExploited).ThenByDescending(r => r.Severity))
                Results.Add(new VulnerabilityRowViewModel(r));
            var exploited = records.Count(r => r.KnownExploited);
            LookupMessage = records.Count == 0
                ? $"No known vulnerabilities for {coordinate.Name} {coordinate.Version}."
                : $"{records.Count} known vulnerabilities, {exploited} known exploited (CISA KEV).";
        }
        catch (InvalidOperationException ex)
        {
            LookupMessage = ex.Message;
        }
        catch (HttpRequestException ex)
        {
            LookupMessage = "Lookup failed: " + ex.Message;
        }
        OnPropertyChanged(nameof(HasResults));
    }

    private static EngineStatusViewModel Create(IntelligenceSourceInfo s) =>
        new(s.Id, s.DisplayName, "Threat intelligence", s.Purpose, s.PlannedPhase, s.SendsDataExternally);
}

public sealed class ScanHistoryRowViewModel(ScanReport report)
{
    public ScanReport Report { get; } = report;
    public string StartedText => DisplayFormat.DateTime(Report.StartedAtUtc);
    public string Folder => Report.RootFolder;
    public string FilesText => DisplayFormat.Count(Report.Statistics.FileCount);
    public string HashedText => DisplayFormat.Count(Report.Statistics.HashedCount);
    public string ErrorsText => DisplayFormat.Count(Report.Statistics.ErrorCount);
    public string FindingsText => DisplayFormat.Count(Report.Findings.Count);
    public string SizeText => DisplayFormat.Bytes(Report.Statistics.TotalBytes);
    public string DurationText => DisplayFormat.Duration(Report.Duration);
    public string ScanIdShort => Report.ScanId.ToString("N", CultureInfo.InvariantCulture)[..8];
}

public sealed class ScanHistoryViewModel(IScanHistoryStore store) : PageViewModel
{
    private ScanHistoryRowViewModel? _selected;

    public override PageKey Key => PageKey.ScanHistory;
    public override string Title => "Scan History";
    public override string Subtitle => "Sessions scanned during this run (persistent history arrives with the Second Brain)";
    public ObservableCollection<ScanHistoryRowViewModel> Items { get; } = [];
    public bool HasItems => Items.Count > 0;
    public bool HasNoItems => Items.Count == 0;
    public ScanHistoryRowViewModel? Selected { get => _selected; set => SetProperty(ref _selected, value); }

    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        Items.Clear();
        foreach (var r in await store.GetRecentAsync(50, cancellationToken).ConfigureAwait(true))
            Items.Add(new ScanHistoryRowViewModel(r));
        OnPropertyChanged(nameof(HasItems));
        OnPropertyChanged(nameof(HasNoItems));
    }
}

public sealed class SettingsViewModel : PageViewModel
{
    private readonly SettingsService _settings;
    private readonly IThemeService _theme;
    private string _excludedDirectoriesText = string.Empty;
    private string _maxHashMegabytesText = string.Empty;
    private int _parallelism;
    private bool _isDarkTheme;
    private bool _allowExternalIntelligence;
    private string _abuseChAuthKey = string.Empty;
    private bool _aiEnabled;
    private string _aiEndpoint = string.Empty;
    private string _aiModel = string.Empty;
    private string _vaultPath = string.Empty;
    private bool _autoRecord;
    private readonly IFolderPicker? _folderPicker;
    private string _saveMessage = string.Empty;
    private bool _claudeFixEnabled;
    private string _claudeCliPath = string.Empty;
    private string _claudeModel = string.Empty;

    public SettingsViewModel(SettingsService settings, IThemeService theme, EngineCatalogViewModel engines, IFolderPicker? folderPicker = null,
        AboutViewModel? about = null, ComponentsViewModel? components = null)
    {
        About = about;
        Components = components;
        _folderPicker = folderPicker;
        BrowseVaultCommand = new RelayCommand(() =>
        {
            if (_folderPicker?.PickFolder(VaultPath.Length > 0 ? VaultPath : null) is { } picked) VaultPath = picked;
        }, () => _folderPicker is not null);
        _settings = settings;
        _theme = theme;
        EngineCatalog = engines;
        SaveCommand = new RelayCommand(Save);
        ResetCommand = new RelayCommand(Reset);
        RunSetupCommand = new RelayCommand(() => SetupRequested?.Invoke(this, EventArgs.Empty));
        LoadFrom(settings.Current);
        settings.Changed += (_, _) =>
        {
            var dark = _settings.Current.Theme == AppTheme.Dark;
            if (_isDarkTheme == dark) return;
            _isDarkTheme = dark;
            OnPropertyChanged(nameof(IsDarkTheme));
        };
    }

    public override PageKey Key => PageKey.Settings;
    public override string Title => "Settings";
    public override string Subtitle => "Engines, privacy and scanning";
    public EngineCatalogViewModel EngineCatalog { get; }
    public ICommand SaveCommand { get; }
    public ICommand ResetCommand { get; }

    /// <summary>Updates and About; null when the host does not provide them (tests).</summary>
    public AboutViewModel? About { get; }
    public bool HasAbout => About is not null;

    /// <summary>Component versions and updates; null when the host does not provide them (tests).</summary>
    public ComponentsViewModel? Components { get; }
    public bool HasComponents => Components is not null;

    /// <summary>Asks the view to scroll to the Components card (after the start-up popup).</summary>
    public event EventHandler? ComponentsRequested;

    /// <summary>Set until the view has scrolled to Components; the page view may be created after the request.</summary>
    public bool ComponentsScrollPending { get; set; }

    public void ShowComponents()
    {
        ComponentsScrollPending = true;
        ComponentsRequested?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Opens the first-run setup wizard again.</summary>
    public ICommand RunSetupCommand { get; }
    public event EventHandler? SetupRequested;

    /// <summary>Shows the saved settings again (after the setup wizard changed them).</summary>
    public void Reload() => LoadFrom(_settings.Current);
    public IReadOnlyList<int> ParallelismOptions { get; } = [1, 2, 4, 8];
    public string SettingsFile => JsonSettingsStore.DefaultPath;

    /// <summary>One directory name per line.</summary>
    public string ExcludedDirectoriesText { get => _excludedDirectoriesText; set => SetProperty(ref _excludedDirectoriesText, value ?? string.Empty); }
    public string MaxHashMegabytesText { get => _maxHashMegabytesText; set => SetProperty(ref _maxHashMegabytesText, value ?? string.Empty); }
    public int Parallelism { get => _parallelism; set => SetProperty(ref _parallelism, value); }
    public bool AllowExternalIntelligence { get => _allowExternalIntelligence; set => SetProperty(ref _allowExternalIntelligence, value); }
    public string AbuseChAuthKey { get => _abuseChAuthKey; set => SetProperty(ref _abuseChAuthKey, value?.Trim() ?? string.Empty); }
    public bool AiEnabled { get => _aiEnabled; set => SetProperty(ref _aiEnabled, value); }
    public string AiEndpoint { get => _aiEndpoint; set => SetProperty(ref _aiEndpoint, value?.Trim() ?? string.Empty); }
    public string AiModel { get => _aiModel; set => SetProperty(ref _aiModel, value?.Trim() ?? string.Empty); }
    public string VaultPath { get => _vaultPath; set => SetProperty(ref _vaultPath, value?.Trim().Trim('"') ?? string.Empty); }
    public bool AutoRecord { get => _autoRecord; set => SetProperty(ref _autoRecord, value); }
    public ICommand BrowseVaultCommand { get; }
    public bool ClaudeFixEnabled { get => _claudeFixEnabled; set => SetProperty(ref _claudeFixEnabled, value); }
    public string ClaudeCliPath { get => _claudeCliPath; set => SetProperty(ref _claudeCliPath, value?.Trim().Trim('"') ?? string.Empty); }
    public string ClaudeModel { get => _claudeModel; set => SetProperty(ref _claudeModel, value?.Trim() ?? string.Empty); }

    /// <summary>Executable path (empty = auto-detect) and on/off switch per CLI engine.</summary>
    public ObservableCollection<EngineSettingViewModel> EngineSettings { get; } = [];
    public string SaveMessage { get => _saveMessage; private set => SetProperty(ref _saveMessage, value); }

    public bool IsDarkTheme
    {
        get => _isDarkTheme;
        set
        {
            if (!SetProperty(ref _isDarkTheme, value)) return;
            var theme = value ? AppTheme.Dark : AppTheme.Light;
            _theme.Apply(theme);
            _settings.Update(s => s with { Theme = theme });
        }
    }

    public event EventHandler? Saved;

    internal void Save()
    {
        if (!int.TryParse(MaxHashMegabytesText, NumberStyles.Integer, CultureInfo.CurrentCulture, out var mb) || mb is < 1 or > 4096)
        {
            SaveMessage = "Hash limit must be a whole number between 1 and 4096 MB.";
            return;
        }

        if (!Uri.TryCreate(AiEndpoint, UriKind.Absolute, out var aiUri) || !aiUri.IsLoopback)
        {
            SaveMessage = "AI endpoint must be a local URL such as " + AppSettings.DefaultAiEndpoint + ".";
            return;
        }

        if (VaultPath.Length > 0 && !Directory.Exists(VaultPath))
        {
            SaveMessage = "Second Brain vault folder not found. Create it (or open it in Obsidian) first.";
            return;
        }

        if (ClaudeCliPath.Length > 0 && !Path.IsPathFullyQualified(ClaudeCliPath))
        {
            SaveMessage = "Claude Code: path to claude.exe must be absolute (or empty to auto-detect).";
            return;
        }

        var badPath = EngineSettings.FirstOrDefault(e => e.ExecutablePath.Length > 0 && !Path.IsPathFullyQualified(e.ExecutablePath));
        if (badPath is not null)
        {
            SaveMessage = $"{badPath.Name}: executable path must be absolute (or empty to auto-detect).";
            return;
        }

        var excluded = ExcludedDirectoriesText
            .Split(['\r', '\n', ',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        _settings.Update(s => s with
        {
            ExcludedDirectories = excluded,
            MaxHashMegabytes = mb,
            MaxDegreeOfParallelism = Math.Clamp(Parallelism, 1, 16),
            AllowExternalIntelligence = AllowExternalIntelligence,
            AbuseChAuthKey = AbuseChAuthKey.Length == 0 ? null : AbuseChAuthKey,
            AiEnabled = AiEnabled,
            AiEndpoint = AiEndpoint,
            AiModel = AiModel.Length == 0 ? null : AiModel,
            SecondBrainVaultPath = VaultPath.Length == 0 ? null : VaultPath,
            SecondBrainAutoRecord = AutoRecord,
            ClaudeFixEnabled = ClaudeFixEnabled,
            ClaudeCliPath = ClaudeCliPath.Length == 0 ? null : ClaudeCliPath,
            ClaudeModel = ClaudeModel.Length == 0 ? null : ClaudeModel,
            EngineExecutables = EngineSettings.Where(e => e.ExecutablePath.Length > 0)
                .ToDictionary(e => e.Id, e => e.ExecutablePath, StringComparer.OrdinalIgnoreCase),
            DisabledEngines = EngineSettings.Where(e => !e.Enabled).Select(e => e.Id).ToArray(),
        });
        LoadFrom(_settings.Current);
        SaveMessage = "Settings saved. They apply to the next scan.";
        Saved?.Invoke(this, EventArgs.Empty);
    }

    private void Reset()
    {
        var defaults = new AppSettings();
        ExcludedDirectoriesText = string.Join(Environment.NewLine, defaults.ExcludedDirectories);
        MaxHashMegabytesText = defaults.MaxHashMegabytes.ToString(CultureInfo.CurrentCulture);
        Parallelism = defaults.MaxDegreeOfParallelism;
        AllowExternalIntelligence = false;
        AiEnabled = defaults.AiEnabled;
        AiEndpoint = defaults.AiEndpoint;
        AiModel = string.Empty;
        AutoRecord = defaults.SecondBrainAutoRecord;
        ClaudeFixEnabled = defaults.ClaudeFixEnabled;
        ClaudeCliPath = string.Empty;
        ClaudeModel = string.Empty;
        foreach (var engine in EngineSettings)
        {
            engine.ExecutablePath = string.Empty;
            engine.Enabled = true;
        }
        SaveMessage = "Defaults restored. Press Save to apply.";
    }

    private void LoadFrom(AppSettings s)
    {
        ExcludedDirectoriesText = string.Join(Environment.NewLine, s.ExcludedDirectories);
        MaxHashMegabytesText = s.MaxHashMegabytes.ToString(CultureInfo.CurrentCulture);
        Parallelism = s.MaxDegreeOfParallelism;
        AllowExternalIntelligence = s.AllowExternalIntelligence;
        AbuseChAuthKey = s.AbuseChAuthKey ?? string.Empty;
        AiEnabled = s.AiEnabled;
        AiEndpoint = s.AiEndpoint;
        AiModel = s.AiModel ?? string.Empty;
        VaultPath = s.SecondBrainVaultPath ?? string.Empty;
        AutoRecord = s.SecondBrainAutoRecord;
        ClaudeFixEnabled = s.ClaudeFixEnabled;
        ClaudeCliPath = s.ClaudeCliPath ?? string.Empty;
        ClaudeModel = s.ClaudeModel ?? string.Empty;
        EngineSettings.Clear();
        foreach (var engine in EngineCatalog.Engines.Where(e => !string.Equals(e.Id, "malware-hash", StringComparison.Ordinal)))
        {
            EngineSettings.Add(new EngineSettingViewModel(engine.Id, engine.Name,
                s.EngineExecutables.TryGetValue(engine.Id, out var path) ? path : string.Empty,
                !s.DisabledEngines.Contains(engine.Id, StringComparer.OrdinalIgnoreCase)));
        }
        _isDarkTheme = s.Theme == AppTheme.Dark;
        OnPropertyChanged(nameof(IsDarkTheme));
    }
}
