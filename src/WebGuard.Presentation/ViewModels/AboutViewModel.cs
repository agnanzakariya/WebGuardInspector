using System.Collections.ObjectModel;
using System.Runtime.InteropServices;
using System.Windows.Input;
using WebGuard.Core;
using WebGuard.Core.AI;
using WebGuard.Core.Detection;
using WebGuard.Core.Fixing;
using WebGuard.Core.Updates;
using WebGuard.Presentation.Formatting;
using WebGuard.Presentation.Mvvm;
using WebGuard.Presentation.Services;

namespace WebGuard.Presentation.ViewModels;

/// <summary>Folders and files shown in About; supplied by the host because they depend on how the app was installed.</summary>
public sealed record AboutPaths(
    string InstallFolder,
    string SettingsFile,
    string LogsFolder,
    string FixBackupsFolder,
    string UpdatesFolder,
    string IntelligenceCacheFolder,
    string McpServer,
    string LicensesFolder);

public sealed record ComponentRow(string Name, string Version, string Detail, StatusTone Tone);

public sealed record LocationRow(string Label, string Path, ICommand OpenCommand);

public sealed record LicenseRow(string Component, string License, string Usage, ICommand OpenCommand);

/// <summary>
/// Settings → Updates and About. Updates come from the GitHub Releases of the app's repository: checked at start-up at
/// most once a day when enabled (only release metadata is requested) or on demand; installing downloads the setup,
/// verifies its published SHA-256 and runs it after the person confirms.
/// </summary>
public sealed class AboutViewModel : ObservableObject
{
    public const string RepositoryUrl = "https://github.com/agnanzakariya/WebGuardInspector";
    private static readonly TimeSpan StartupCheckInterval = TimeSpan.FromHours(20);

    private readonly SettingsService _settings;
    private readonly IUpdateService? _updates;
    private readonly IAiSecurityAnalyst? _analyst;
    private readonly ICodeFixer? _fixer;
    private readonly IExternalLauncher? _launcher;
    private readonly IDialogService? _dialogs;
    private readonly IInstallerLauncher? _installer;
    private readonly TimeProvider _time;
    private string _updateStatus;
    private StatusTone _updateTone;
    private ReleaseInfo? _latest;
    private bool _isUpdateAvailable;
    private bool _isBusy;
    private double _progress;

    public AboutViewModel(SettingsService settings, EngineCatalogViewModel engines, AboutPaths paths, IUpdateService? updates = null,
        IAiSecurityAnalyst? analyst = null, ICodeFixer? fixer = null, IExternalLauncher? launcher = null, IDialogService? dialogs = null,
        IInstallerLauncher? installer = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(paths);
        _settings = settings;
        _updates = updates;
        _analyst = analyst;
        _fixer = fixer;
        _launcher = launcher;
        _dialogs = dialogs;
        _installer = installer;
        _time = timeProvider ?? TimeProvider.System;
        EngineCatalog = engines;
        Paths = paths;
        // The start-up check runs at most once a day, so a recent check is only reported, not repeated.
        _updateStatus = settings.Current.LastUpdateCheckUtc is null
            ? "Not checked yet."
            : "Checked recently (see below). Press Check now to look again.";

        CheckNowCommand = new AsyncRelayCommand(() => CheckAsync(), () => _updates is not null && !IsBusy, ex => SetStatus("Update check failed: " + ex.Message, StatusTone.Danger));
        InstallUpdateCommand = new AsyncRelayCommand(InstallAsync, () => CanInstall && !IsBusy, ex => SetStatus(ex.Message, StatusTone.Danger));
        OpenReleaseCommand = new RelayCommand(() => Open((Latest?.PageUrl ?? _updates?.ReleasesPage)?.AbsoluteUri ?? RepositoryUrl + "/releases"));
        OpenRepositoryCommand = new RelayCommand(() => Open(RepositoryUrl));
        OpenIssuesCommand = new RelayCommand(() => Open(RepositoryUrl + "/issues"));
        RefreshComponentsCommand = new AsyncRelayCommand(() => RefreshComponentsAsync());

        Locations =
        [
            Location("Installed in", paths.InstallFolder),
            Location("Settings file", paths.SettingsFile),
            Location("Logs", paths.LogsFolder),
            Location("Fix backups", paths.FixBackupsFolder),
            Location("Downloaded updates", paths.UpdatesFolder),
            Location("Intelligence cache", paths.IntelligenceCacheFolder),
        ];
        Licenses =
        [
            License("Gitleaks", "MIT", "Bundled (tools\\gitleaks.exe)", "gitleaks-LICENSE.txt", "https://github.com/gitleaks/gitleaks/blob/master/LICENSE"),
            License("OSV-Scanner", "Apache-2.0", "Bundled (tools\\osv-scanner.exe)", "osv-scanner-LICENSE.txt", "https://github.com/google/osv-scanner/blob/main/LICENSE"),
            License("YARA-X", "BSD-3-Clause", "Bundled (tools\\yr.exe)", "yara-x-LICENSE.txt", "https://github.com/VirusTotal/yara-x/blob/main/LICENSE"),
            License(".NET runtime", "MIT", "Bundled (self-contained app)", null, "https://github.com/dotnet/runtime/blob/main/LICENSE.TXT"),
            License("Inno Setup", "Inno Setup License", "Installer and uninstaller", null, "https://jrsoftware.org/files/is/license.txt"),
            License("Semgrep CE", "LGPL-2.1", "Installed separately (pip)", null, "https://github.com/semgrep/semgrep/blob/develop/LICENSE"),
            License("Claude Code", "Anthropic terms", "Installed separately; used with your Claude account", null, "https://www.anthropic.com/legal/commercial-terms"),
        ];
        _settings.Changed += (_, _) => OnPropertyChanged(nameof(VaultLocation));
    }

    // ---- Identity ------------------------------------------------------------------------------------------------

    public string Brand => AppInfo.Brand;
    public string Product => AppInfo.Product;
    public string Version => AppInfo.Version;
    public string VersionText => "Version " + AppInfo.Version;
    public string Description =>
        "Local source-security workspace: inventory and hashing, Semgrep, Gitleaks, OSV-Scanner and YARA-X, threat intelligence, " +
        "a local AI analyst, fixing with Claude and a Second Brain in Obsidian. Source code stays on this PC unless you allow otherwise.";
    public string Author => "Agnan Zakariya";
    public string Repository => RepositoryUrl;
    public ICommand OpenRepositoryCommand { get; }
    public ICommand OpenIssuesCommand { get; }

    // ---- Updates -------------------------------------------------------------------------------------------------

    public bool AutoCheck
    {
        get => _settings.Current.CheckForUpdates;
        set
        {
            if (value == _settings.Current.CheckForUpdates) return;
            _settings.Update(s => s with { CheckForUpdates = value });
            OnPropertyChanged();
        }
    }

    public string UpdateStatus { get => _updateStatus; private set => SetProperty(ref _updateStatus, value); }
    public StatusTone Tone { get => _updateTone; private set => SetProperty(ref _updateTone, value); }

    public string LastCheckedText => _settings.Current.LastUpdateCheckUtc is { } at
        ? "Last checked " + DisplayFormat.DateTime(at)
        : "Never checked";

    public ReleaseInfo? Latest
    {
        get => _latest;
        private set
        {
            if (!SetProperty(ref _latest, value)) return;
            foreach (var n in new[] { nameof(HasReleaseNotes), nameof(ReleaseTitle), nameof(ReleaseNotes), nameof(CanInstall), nameof(InstallHint) })
                OnPropertyChanged(n);
            InstallUpdateCommand.RaiseCanExecuteChanged();
        }
    }

    public bool IsUpdateAvailable
    {
        get => _isUpdateAvailable;
        private set
        {
            if (!SetProperty(ref _isUpdateAvailable, value)) return;
            foreach (var n in new[] { nameof(HasReleaseNotes), nameof(CanInstall), nameof(UpdateBadge) }) OnPropertyChanged(n);
            InstallUpdateCommand.RaiseCanExecuteChanged();
        }
    }

    /// <summary>Short text for the top bar, e.g. "Update 0.8.0 available".</summary>
    public string UpdateBadge => IsUpdateAvailable && Latest is not null ? $"Update {Latest.Version} available" : string.Empty;
    public bool HasReleaseNotes => IsUpdateAvailable && Latest is not null;
    public string ReleaseTitle => Latest is null ? string.Empty
        : Latest.Name + (Latest.PublishedAtUtc is { } p ? " · " + DisplayFormat.DateTime(p) : string.Empty);
    public string ReleaseNotes => Latest?.Notes.Trim() is { Length: > 0 } notes ? notes : "No release notes.";
    public bool CanInstall => IsUpdateAvailable && Latest is { SetupUrl: not null, Sha256: not null } && _installer is not null;

    public string InstallHint => Latest switch
    {
        null => string.Empty,
        { SetupUrl: null } => "This release has no Windows installer; open the release page.",
        { Sha256: null } => "No SHA-256 was published for the installer, so it is not installed automatically; open the release page.",
        _ => $"{Latest.SetupFileName} · {DisplayFormat.Bytes(Latest.SetupSize ?? 0)} · SHA-256 {Latest.Sha256![..16]}…",
    };

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (!SetProperty(ref _isBusy, value)) return;
            CheckNowCommand.RaiseCanExecuteChanged();
            InstallUpdateCommand.RaiseCanExecuteChanged();
        }
    }

    public double Progress { get => _progress; private set => SetProperty(ref _progress, value); }

    public AsyncRelayCommand CheckNowCommand { get; }
    public AsyncRelayCommand InstallUpdateCommand { get; }
    public ICommand OpenReleaseCommand { get; }

    /// <summary>Start-up check: only when enabled and the last check is older than about a day.</summary>
    public async Task CheckOnStartupAsync(CancellationToken cancellationToken = default)
    {
        if (_updates is null || !_settings.Current.CheckForUpdates) return;
        if (_settings.Current.LastUpdateCheckUtc is { } last && _time.GetUtcNow() - last < StartupCheckInterval) return;
        await CheckAsync(cancellationToken).ConfigureAwait(true);
    }

    public async Task CheckAsync(CancellationToken cancellationToken = default)
    {
        if (_updates is null || IsBusy) return;
        IsBusy = true;
        SetStatus("Checking GitHub for a newer version…", StatusTone.Neutral);
        try
        {
            var result = await _updates.CheckAsync(cancellationToken).ConfigureAwait(true);
            if (result.Error is null) _settings.Update(s => s with { LastUpdateCheckUtc = result.CheckedAtUtc });
            OnPropertyChanged(nameof(LastCheckedText));
            Latest = result.Latest;
            IsUpdateAvailable = result.IsNewer;
            if (result.Error is not null) SetStatus(result.Error, StatusTone.Warning);
            else if (result.IsNewer) SetStatus($"Version {result.Latest!.Version} is available (you have {result.CurrentVersion}).", StatusTone.Info);
            else if (result.Latest is null) SetStatus($"You have version {result.CurrentVersion}. No release has been published yet.", StatusTone.Success);
            else SetStatus($"You have the latest version ({result.CurrentVersion}).", StatusTone.Success);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task InstallAsync()
    {
        if (_updates is null || _installer is null || Latest is not { } release || !CanInstall) return;
        var question = $"Download {release.SetupFileName} ({DisplayFormat.Bytes(release.SetupSize ?? 0)}) from GitHub, check its SHA-256 and run it?" +
                       "\n\nAzura closes while the installer runs. Your settings, backups and vault are kept.";
        if (_dialogs?.Confirm("Install update " + release.Version, question) == false) return;

        IsBusy = true;
        Progress = 0;
        SetStatus("Downloading the installer…", StatusTone.Neutral);
        try
        {
            var progress = new Progress<double>(p => Progress = p);
            var path = await _updates.DownloadAsync(release, progress, CancellationToken.None).ConfigureAwait(true);
            SetStatus("SHA-256 verified. Starting the installer…", StatusTone.Success);
            _installer.RunAndExit(path);
        }
        finally
        {
            IsBusy = false;
        }
    }

    // ---- Components and locations --------------------------------------------------------------------------------

    public EngineCatalogViewModel EngineCatalog { get; }
    public AboutPaths Paths { get; }
    public ObservableCollection<ComponentRow> Components { get; } = [];
    public AsyncRelayCommand RefreshComponentsCommand { get; }
    public IReadOnlyList<LocationRow> Locations { get; }
    public IReadOnlyList<LicenseRow> Licenses { get; }

    public LocationRow VaultLocation => Location("Second Brain vault", _settings.Current.SecondBrainVaultPath ?? "(not used)");

    public async Task RefreshComponentsAsync(CancellationToken cancellationToken = default)
    {
        var rows = new List<ComponentRow>
        {
            new(AppInfo.Name, AppInfo.Version, Paths.InstallFolder, StatusTone.Success),
            new("MCP server", File.Exists(Paths.McpServer) ? AppInfo.Version : "not found", Paths.McpServer,
                File.Exists(Paths.McpServer) ? StatusTone.Success : StatusTone.Warning),
            new(".NET runtime", Environment.Version.ToString(), RuntimeInformation.FrameworkDescription + " · " + RuntimeInformation.ProcessArchitecture, StatusTone.Neutral),
            new("Windows", Environment.OSVersion.Version.ToString(), RuntimeInformation.OSDescription.Trim(), StatusTone.Neutral),
        };
        if (_fixer is not null) rows.Add(Row("Claude Code", await _fixer.GetStatusAsync(cancellationToken).ConfigureAwait(true)));
        if (_analyst is not null) rows.Add(Row("Local AI analyst", await _analyst.GetStatusAsync(cancellationToken).ConfigureAwait(true)));
        Components.Clear();
        foreach (var row in rows) Components.Add(row);
    }

    private static ComponentRow Row(string name, EngineStatus status) => new(
        name,
        status.Version ?? status.Availability.ToString(),
        status.Message ?? string.Empty,
        status.Availability switch
        {
            EngineAvailability.Ready => StatusTone.Success,
            EngineAvailability.Disabled => StatusTone.Neutral,
            EngineAvailability.Error => StatusTone.Danger,
            _ => StatusTone.Warning,
        });

    private LocationRow Location(string label, string path) =>
        new(label, path, new RelayCommand(() => OpenPath(path), () => _launcher is not null && Path.IsPathFullyQualified(path)));

    private LicenseRow License(string component, string license, string usage, string? file, string url)
    {
        var local = file is null ? null : Path.Combine(Paths.LicensesFolder, file);
        return new LicenseRow(component, license, usage,
            new RelayCommand(() => { if (local is not null && File.Exists(local)) OpenPath(local); else Open(url); }));
    }

    private void OpenPath(string path)
    {
        if (Path.IsPathFullyQualified(path)) _launcher?.Open(new Uri(path));
    }

    private void Open(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri)) _launcher?.Open(uri);
    }

    private void SetStatus(string text, StatusTone tone)
    {
        UpdateStatus = text;
        Tone = tone;
    }
}
