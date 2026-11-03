using System.Windows;
using System.Windows.Threading;
using System.Net.Http;
using WebGuard.AI;
using WebGuard.Core;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Intelligence;
using WebGuard.Desktop.Services;
using WebGuard.Detection;
using WebGuard.Intelligence;
using WebGuard.Persistence;
using WebGuard.Presentation.Services;
using WebGuard.Presentation.ViewModels;
using WebGuard.Scanner;

namespace WebGuard.Desktop;

public partial class App : Application
{
    private ShellViewModel? _shell;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnDispatcherUnhandledException;

        var theme = new ThemeService();
        _shell = Compose(theme);
        var window = new MainWindow(_shell, theme);
        MainWindow = window;
        window.Show();
        await _shell.InitializeAsync();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _shell?.Dispose();
        base.OnExit(e);
    }

    /// <summary>
    /// Composition root. Hand-wired to keep the app free of NuGet dependencies.
    /// Engines and intelligence sources read settings on every call, so Settings changes apply without a restart.
    /// </summary>
    private static ShellViewModel Compose(ThemeService theme)
    {
        var settings = new SettingsService(new JsonSettingsStore(JsonSettingsStore.DefaultPath));
        var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"WebGuardInspector/{AppInfo.Version}");
        var cache = new FileIntelligenceCache(FileIntelligenceCache.DefaultDirectory);
        IntelligenceSettings Intelligence() => new(settings.Current.AllowExternalIntelligence, settings.Current.AbuseChAuthKey);
        var kev = new CisaKevCatalog(http, cache);
        var vulnerabilities = new OsvVulnerabilityIntelligence(http, cache, Intelligence, kev: kev);
        IMalwareHashIntelligence[] malware =
        [
            new MalwareBazaarHashIntelligence(http, cache, Intelligence),
            new ThreatFoxHashIntelligence(http, cache, Intelligence),
        ];

        IReadOnlyList<ISecurityEngine> engines =
        [
            .. SecurityEngineCatalog.CreateDefault(new ExternalProcessRunner(), id => settings.Current.ToolOptions(id)),
            new MalwareHashLookupEngine(malware),
        ];
        IFindingEnricher[] enrichers = [new KnownExploitedEnricher(kev, Intelligence)];

        // Local model calls can take minutes on CPU; each analysis has its own timeout instead of the client's.
        var aiHttp = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
        AiSettings Ai() => new(settings.Current.AiEnabled, settings.Current.AiEndpoint, settings.Current.AiModel);
        var analyst = new LocalAiSecurityAnalyst(new OpenAiCompatibleClient(aiHttp), Ai);
        var mcp = new StdioMcpServerHost(StdioMcpServerHost.BundledExecutablePath);
        var clipboard = new ClipboardService();
        var dialogs = new DialogService();
        var launcher = new ExternalLauncher(dialogs);
        var folderPicker = new FolderPicker();
        var secondBrain = new ObsidianSecondBrain(() => new SecondBrainSettings(settings.Current.SecondBrainVaultPath),
            new LocalEmbeddingService(new OpenAiCompatibleClient(aiHttp), Ai));
        var history = new InMemoryScanHistoryStore();

        var workspace = new ScanWorkspaceViewModel(
            new LocalFolderScanner(engines, enrichers),
            new JsonReportExporter(),
            history,
            settings,
            folderPicker,
            new SaveFileDialogService(),
            clipboard,
            dialogs,
            secondBrain);

        var catalog = new EngineCatalogViewModel(engines);
        var findings = new FindingsViewModel(catalog, analyst, secondBrain, settings, launcher);

        return new ShellViewModel(
            workspace,
            new OverviewViewModel(workspace, findings, catalog),
            new LocalScannerViewModel(workspace, settings),
            findings,
            new AiAnalystViewModel(analyst, mcp, workspace, clipboard),
            new SecondBrainViewModel(secondBrain, launcher),
            new IntelligenceViewModel(vulnerabilities, malware),
            new ScanHistoryViewModel(history),
            new SettingsViewModel(settings, theme, catalog, folderPicker),
            catalog,
            settings,
            theme);
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(e.Exception.Message, "WebGuard Inspector — unexpected error", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
