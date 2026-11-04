using System.IO;
using System.Windows;
using System.Windows.Threading;
using System.Net.Http;
using WebGuard.AI;
using WebGuard.Core;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Fixing;
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

        // Local model calls can take minutes on CPU; each analysis has its own timeout instead of the client's.
        var aiHttp = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
        AiSettings Ai() => new(settings.Current.AiEnabled, settings.Current.AiEndpoint, settings.Current.AiModel);
        var secondBrain = new ObsidianSecondBrain(() => new SecondBrainSettings(settings.Current.SecondBrainVaultPath),
            new LocalEmbeddingService(new OpenAiCompatibleClient(aiHttp), Ai));

        var processRunner = new ExternalProcessRunner();
        IReadOnlyList<ISecurityEngine> engines =
        [
            // First: files identical to ones you confirmed as malicious need no engine or lookup.
            new SecondBrainMemoryEngine(secondBrain, () => settings.Current.SecondBrainFirst),
            .. SecurityEngineCatalog.CreateDefault(processRunner, id => settings.Current.ToolOptions(id)),
            new MalwareHashLookupEngine(malware),
        ];
        IFindingEnricher[] enrichers = [new KnownExploitedEnricher(kev, Intelligence)];
        var analyst = new LocalAiSecurityAnalyst(new OpenAiCompatibleClient(aiHttp), Ai);
        var mcp = new StdioMcpServerHost(StdioMcpServerHost.BundledExecutablePath);
        var clipboard = new ClipboardService();
        var dialogs = new DialogService();
        var launcher = new ExternalLauncher(dialogs);
        var folderPicker = new FolderPicker();
        var history = new InMemoryScanHistoryStore();

        var workspace = new ScanWorkspaceViewModel(
            new LocalFolderScanner(engines, enrichers, resultCache: new FileScanResultCacheStore(FileScanResultCacheStore.DefaultDirectory)),
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
        var claudeFixer = new ClaudeCodeFixer(processRunner,
            () => new ClaudeCodeSettings(settings.Current.ClaudeFixEnabled, settings.Current.ClaudeCliPath, settings.Current.ClaudeModel),
            () => ExecutableLocator.Find(["claude"]));
        // The local fixer uses the AI Analyst's endpoint and model; Settings decides which one the Fixing page uses.
        var localFixer = new LocalModelCodeFixer(new OpenAiCompatibleClient(aiHttp),
            () => new AiSettings(true, settings.Current.AiEndpoint, settings.Current.AiModel), () => settings.Current.ClaudeFixEnabled);
        var fixer = new SelectableCodeFixer(() => settings.Current.FixProvider == FixProvider.LocalModel, claudeFixer, localFixer);
        var fixing = new FixingViewModel(findings, fixer, new FixApplier(FixApplier.DefaultBackupRoot), secondBrain, settings, clipboard);
        var setup = new SetupWizardViewModel(settings, theme, catalog, analyst, fixer, secondBrain, folderPicker);

        // Large installer downloads: no client-wide timeout; the update check has its own.
        var updateHttp = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
        updateHttp.DefaultRequestHeaders.UserAgent.ParseAdd($"WebGuardInspector/{AppInfo.Version}");
        var updates = new GitHubUpdateService(updateHttp, "agnanzakariya", "WebGuardInspector", GitHubUpdateService.DefaultDownloadFolder);
        var dataRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WebGuardInspector");
        var about = new AboutViewModel(settings, catalog,
            new AboutPaths(
                AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar),
                JsonSettingsStore.DefaultPath,
                Path.Combine(dataRoot, "logs"),
                FixApplier.DefaultBackupRoot,
                GitHubUpdateService.DefaultDownloadFolder,
                FileIntelligenceCache.DefaultDirectory,
                StdioMcpServerHost.BundledExecutablePath,
                Path.Combine(AppContext.BaseDirectory, "tools", "licenses")),
            updates, analyst, claudeFixer, launcher, dialogs, new InstallerLauncher());
        var componentHttp = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        componentHttp.DefaultRequestHeaders.UserAgent.ParseAdd($"WebGuardInspector/{AppInfo.Version}");
        var components = new ComponentsViewModel(engines, catalog,
            new ComponentUpdateService(componentHttp, processRunner, Path.Combine(AppContext.BaseDirectory, "tools"),
                () => ExecutableLocator.Find(["winget"]),
                [new ClamAvSignatureDatabase(processRunner, () => ClamscanPath(settings.Current))]),
            claudeFixer, dialogs);

        return new ShellViewModel(
            workspace,
            new OverviewViewModel(workspace, findings, catalog),
            new LocalScannerViewModel(workspace, settings),
            findings,
            fixing,
            new AiAnalystViewModel(analyst, mcp, workspace, clipboard),
            new SecondBrainViewModel(secondBrain, launcher),
            new IntelligenceViewModel(vulnerabilities, malware),
            new ScanHistoryViewModel(history),
            new SettingsViewModel(settings, theme, catalog, folderPicker, about, components),
            catalog,
            settings,
            theme,
            setup);
    }

    /// <summary>clamscan.exe from Settings, else the installed one (freshclam.exe lives next to it).</summary>
    private static string? ClamscanPath(AppSettings s) =>
        s.EngineExecutables.TryGetValue(ClamAvEngine.Id, out var configured) && File.Exists(configured)
            ? configured
            : ExecutableLocator.Find(["clamscan"]);

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(e.Exception.Message, AppInfo.Name + " — unexpected error", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
