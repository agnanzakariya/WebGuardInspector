using System.Collections.ObjectModel;
using System.Windows.Input;
using WebGuard.Core;
using WebGuard.Core.Scanning;
using WebGuard.Presentation.Mvvm;
using WebGuard.Presentation.Services;

namespace WebGuard.Presentation.ViewModels;

public sealed class NavItemViewModel(PageKey key, string title, string glyph, string? phase = null) : ObservableObject
{
    private int _badge;

    public PageKey Key { get; } = key;
    public string Title { get; } = title;

    /// <summary>Segoe Fluent Icons / MDL2 code point.</summary>
    public string Glyph { get; } = glyph;

    /// <summary>"Phase 3" style tag for features that are still interface-only.</summary>
    public string? Phase { get; } = phase;
    public bool HasPhase => Phase is not null;

    public int Badge
    {
        get => _badge;
        set { if (SetProperty(ref _badge, value)) OnPropertyChanged(nameof(HasBadge)); }
    }

    public bool HasBadge => Badge > 0;
}

public sealed class ShellViewModel : ObservableObject, IDisposable
{
    private readonly Dictionary<PageKey, PageViewModel> _pages;
    private readonly SettingsService _settings;
    private readonly IThemeService _theme;
    private NavItemViewModel? _selectedNav;
    private PageViewModel _currentPage;

    public ShellViewModel(
        ScanWorkspaceViewModel workspace,
        OverviewViewModel overview,
        LocalScannerViewModel scanner,
        FindingsViewModel findings,
        AiAnalystViewModel ai,
        SecondBrainViewModel secondBrain,
        IntelligenceViewModel intelligence,
        ScanHistoryViewModel history,
        SettingsViewModel settingsPage,
        EngineCatalogViewModel engines,
        SettingsService settings,
        IThemeService theme)
    {
        ArgumentNullException.ThrowIfNull(workspace);
        ArgumentNullException.ThrowIfNull(settingsPage);
        Workspace = workspace;
        Engines = engines;
        _settings = settings;
        _theme = theme;
        _pages = new PageViewModel[] { overview, scanner, findings, ai, secondBrain, intelligence, history, settingsPage }
            .ToDictionary(p => p.Key);

        NavItems =
        [
            new(PageKey.Overview, "Overview", ""),
            new(PageKey.LocalScanner, "Local Scanner", ""),
            new(PageKey.Findings, "Findings", ""),
            new(PageKey.AiAnalyst, "AI Analyst", "", "Phase 3"),
            new(PageKey.SecondBrain, "Second Brain", "", "Phase 4"),
            new(PageKey.Intelligence, "Intelligence", ""),
            new(PageKey.ScanHistory, "Scan History", ""),
            new(PageKey.Settings, "Settings", ""),
        ];

        _currentPage = overview;
        _selectedNav = NavItems[0];
        NavigateCommand = new RelayCommand<object>(p => { if (p is PageKey k) Navigate(k); else if (p is string s && Enum.TryParse<PageKey>(s, out var key)) Navigate(key); });
        ToggleThemeCommand = new RelayCommand(ToggleTheme);

        workspace.ScanCompleted += async (_, report) => await OnScanCompletedAsync(report, findings, history).ConfigureAwait(true);
        workspace.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(ScanWorkspaceViewModel.IsScanning) or nameof(ScanWorkspaceViewModel.StatusMessage))
                OnPropertyChanged(nameof(EngineStateText));
        };
        settingsPage.Saved += async (_, _) =>
        {
            scanner.RefreshPolicy();
            await Engines.RefreshAsync().ConfigureAwait(true);
            await intelligence.RefreshAsync().ConfigureAwait(true);
        };
        settings.Changed += (_, _) => OnPropertyChanged(nameof(IsDarkTheme));
    }

    public string AppName => AppInfo.Name;
    public string AppTagline => AppInfo.Tagline;
    public string VersionText => "v" + AppInfo.Version;
    public ScanWorkspaceViewModel Workspace { get; }
    public EngineCatalogViewModel Engines { get; }
    public ObservableCollection<NavItemViewModel> NavItems { get; }
    public ICommand NavigateCommand { get; }
    public ICommand ToggleThemeCommand { get; }

    public bool IsDarkTheme => _theme.Current == AppTheme.Dark;
    public string EngineStateText => Workspace.IsScanning ? "Scanning…" : "Ready";

    public NavItemViewModel? SelectedNav
    {
        get => _selectedNav;
        set
        {
            if (value is null || !SetProperty(ref _selectedNav, value)) return;
            CurrentPage = _pages[value.Key];
        }
    }

    public PageViewModel CurrentPage
    {
        get => _currentPage;
        private set => SetProperty(ref _currentPage, value);
    }

    public T Page<T>() where T : PageViewModel => _pages.Values.OfType<T>().Single();

    public void Navigate(PageKey key) => SelectedNav = NavItems.First(n => n.Key == key);

    public async Task InitializeAsync()
    {
        _theme.Apply(_settings.Current.Theme);
        OnPropertyChanged(nameof(IsDarkTheme));
        await Engines.RefreshAsync().ConfigureAwait(true);
        await Page<AiAnalystViewModel>().RefreshAsync().ConfigureAwait(true);
        await Page<SecondBrainViewModel>().RefreshAsync().ConfigureAwait(true);
        await Page<IntelligenceViewModel>().RefreshAsync().ConfigureAwait(true);
    }

    public void Dispose() => Workspace.Dispose();

    private async Task OnScanCompletedAsync(ScanReport report, FindingsViewModel findings, ScanHistoryViewModel history)
    {
        findings.Load(report);
        NavItems.First(n => n.Key == PageKey.Findings).Badge = report.Findings.Count;
        await history.RefreshAsync().ConfigureAwait(true);
    }

    private void ToggleTheme()
    {
        var next = _theme.Current == AppTheme.Dark ? AppTheme.Light : AppTheme.Dark;
        _theme.Apply(next);
        _settings.Update(s => s with { Theme = next });
        OnPropertyChanged(nameof(IsDarkTheme));
    }
}
