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

public enum PageKey { Overview, LocalScanner, Findings, AiAnalyst, SecondBrain, Intelligence, ScanHistory, Settings }

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

public sealed class FindingsViewModel : PageViewModel
{
    private SeveritySummary _summary = SeveritySummary.Empty;
    private FindingItemViewModel? _selected;
    private string _searchText = string.Empty;
    private IReadOnlyList<SecurityFinding> _all = [];
    private ScanReport? _report;

    public FindingsViewModel(EngineCatalogViewModel engines)
    {
        EngineCatalog = engines;
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
        set { if (SetProperty(ref _selected, value)) OnPropertyChanged(nameof(HasSelectedFinding)); }
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
        Summary = SeveritySummary.From(_all);
        EngineRuns.Clear();
        foreach (var run in report.Engines) EngineRuns.Add(new EngineRunViewModel(run));
        OnPropertyChanged(nameof(HasEngineRuns));
        OnPropertyChanged(nameof(EmptyTitle));
        OnPropertyChanged(nameof(EmptyMessage));
        Rebuild();
    }

    private void Rebuild()
    {
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
        SelectedFinding = Findings.FirstOrDefault();
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

    public AiAnalystViewModel(IAiSecurityAnalyst analyst, IMcpServerHost mcp)
    {
        _analyst = analyst;
        _mcp = mcp;
        AnalystStatus = new EngineStatusViewModel("ai", analyst.DisplayName, "Local AI", "Explains why a finding is risky, finds similar cases and drafts patches. Never edits files.", "Phase 3");
        McpStatus = new EngineStatusViewModel("mcp", "MCP Server (stdio, local)", "Tool interface", "Least-privilege tools scoped to the selected folder, with audit log and human approval.", "Phase 3");
        Tools = mcp.Tools.Select(t => new McpToolViewModel(t)).ToArray();
    }

    public override PageKey Key => PageKey.AiAnalyst;
    public override string Title => "AI Analyst";
    public override string Subtitle => "Contextual analysis through MCP";
    public EngineStatusViewModel AnalystStatus { get; }
    public EngineStatusViewModel McpStatus { get; }
    public IReadOnlyList<McpToolViewModel> Tools { get; }

    public IReadOnlyList<string> Guardrails { get; } =
    [
        "AI output is a hypothesis until a person validates it; it is never the sole basis for a malicious/safe verdict.",
        "Secrets are redacted before any context reaches the model.",
        "Runs on a local model (Ollama) by default. Nothing leaves the machine without explicit consent.",
        "Patches are proposed, never applied automatically.",
    ];

    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        AnalystStatus.Apply(await _analyst.GetStatusAsync(cancellationToken).ConfigureAwait(true));
        McpStatus.Apply(await _mcp.GetStatusAsync(cancellationToken).ConfigureAwait(true));
    }
}

public sealed class SecondBrainViewModel : PageViewModel
{
    private readonly ISecondBrainRepository _repository;
    private string _query = string.Empty;
    private string _searchResult = string.Empty;

    public SecondBrainViewModel(ISecondBrainRepository repository)
    {
        _repository = repository;
        Status = new EngineStatusViewModel("secondbrain", "PostgreSQL + pgvector", "Knowledge base", "Verified findings, remediations, false positives and history for semantic retrieval (RAG).", "Phase 4");
        SearchCommand = new AsyncRelayCommand(SearchAsync, () => Query.Trim().Length > 0);
    }

    public override PageKey Key => PageKey.SecondBrain;
    public override string Title => "Second Brain";
    public override string Subtitle => "Cases, solutions and history";
    public EngineStatusViewModel Status { get; }
    public AsyncRelayCommand SearchCommand { get; }

    public string Query
    {
        get => _query;
        set { if (SetProperty(ref _query, value ?? string.Empty)) SearchCommand.RaiseCanExecuteChanged(); }
    }

    public string SearchResult { get => _searchResult; private set => SetProperty(ref _searchResult, value); }

    public IReadOnlyList<string> Lifecycle { get; } = ["Detect", "Correlate", "Analyze", "Validate", "Remember", "Reuse"];

    public IReadOnlyList<LabeledValue> Entities { get; } =
    [
        new("Projects", "Local path, identity, languages"),
        new("Scan Sessions", "Time, commit, engine versions, parameters"),
        new("Security Findings", "Rule, CWE/CVE, severity, confidence, fingerprint, status"),
        new("Finding Occurrences", "Per-scan sightings for regression tracking"),
        new("Security Evidence", "Redacted snippets and tool output"),
        new("Threat Intelligence", "Advisory/IOC snapshots with source and sync time"),
        new("Remediation Knowledge", "Validated fixes and reviewer"),
        new("Validation History", "Confirmed, false positive, accepted risk, fixed"),
        new("Knowledge Embeddings", "pgvector embeddings with provenance"),
    ];

    public async Task RefreshAsync(CancellationToken cancellationToken = default) =>
        Status.Apply(await _repository.GetStatusAsync(cancellationToken).ConfigureAwait(true));

    private async Task SearchAsync()
    {
        var hits = await _repository.SearchSimilarAsync(Query.Trim(), 10, CancellationToken.None).ConfigureAwait(true);
        SearchResult = hits.Count == 0
            ? "No knowledge yet. Semantic search becomes available when the Second Brain is connected in Phase 4."
            : $"{hits.Count} similar cases found.";
    }
}

public sealed class IntelligenceViewModel : PageViewModel
{
    private readonly IVulnerabilityIntelligence _vulnerabilities;
    private readonly IMalwareHashIntelligence _malware;
    private string _ecosystem = "npm";
    private string _packageName = string.Empty;
    private string _packageVersion = string.Empty;
    private string _lookupMessage = string.Empty;

    public IntelligenceViewModel(IVulnerabilityIntelligence vulnerabilities, IMalwareHashIntelligence malware)
    {
        _vulnerabilities = vulnerabilities;
        _malware = malware;
        Sources =
        [
            Create(vulnerabilities.Source),
            Create(malware.Source),
        ];
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
        Sources[1].Apply(await _malware.GetStatusAsync(cancellationToken).ConfigureAwait(true));
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
    private string _saveMessage = string.Empty;

    public SettingsViewModel(SettingsService settings, IThemeService theme, EngineCatalogViewModel engines)
    {
        _settings = settings;
        _theme = theme;
        EngineCatalog = engines;
        SaveCommand = new RelayCommand(Save);
        ResetCommand = new RelayCommand(Reset);
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
    public IReadOnlyList<int> ParallelismOptions { get; } = [1, 2, 4, 8];
    public string SettingsFile => JsonSettingsStore.DefaultPath;

    /// <summary>One directory name per line.</summary>
    public string ExcludedDirectoriesText { get => _excludedDirectoriesText; set => SetProperty(ref _excludedDirectoriesText, value ?? string.Empty); }
    public string MaxHashMegabytesText { get => _maxHashMegabytesText; set => SetProperty(ref _maxHashMegabytesText, value ?? string.Empty); }
    public int Parallelism { get => _parallelism; set => SetProperty(ref _parallelism, value); }
    public bool AllowExternalIntelligence { get => _allowExternalIntelligence; set => SetProperty(ref _allowExternalIntelligence, value); }
    public string AbuseChAuthKey { get => _abuseChAuthKey; set => SetProperty(ref _abuseChAuthKey, value?.Trim() ?? string.Empty); }

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
