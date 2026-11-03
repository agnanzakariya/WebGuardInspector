using System.Windows;
using System.Windows.Threading;
using System.Net.Http;
using WebGuard.AI;
using WebGuard.Core;
using WebGuard.Core.Detection;
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
        var vulnerabilities = new OsvVulnerabilityIntelligence(http, cache, Intelligence);
        var malware = new MalwareBazaarHashIntelligence(http, cache, Intelligence);

        IReadOnlyList<ISecurityEngine> engines =
        [
            .. SecurityEngineCatalog.CreateDefault(new ExternalProcessRunner(), id => settings.Current.ToolOptions(id)),
            new MalwareHashLookupEngine(malware),
        ];
        var history = new InMemoryScanHistoryStore();

        var workspace = new ScanWorkspaceViewModel(
            new LocalFolderScanner(engines),
            new JsonReportExporter(),
            history,
            settings,
            new FolderPicker(),
            new SaveFileDialogService(),
            new ClipboardService(),
            new DialogService());

        var catalog = new EngineCatalogViewModel(engines);
        var findings = new FindingsViewModel(catalog);

        return new ShellViewModel(
            workspace,
            new OverviewViewModel(workspace, findings, catalog),
            new LocalScannerViewModel(workspace, settings),
            findings,
            new AiAnalystViewModel(new PlannedAiSecurityAnalyst(), new PlannedMcpServerHost()),
            new SecondBrainViewModel(new PlannedSecondBrainRepository()),
            new IntelligenceViewModel(vulnerabilities, malware),
            new ScanHistoryViewModel(history),
            new SettingsViewModel(settings, theme, catalog),
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
