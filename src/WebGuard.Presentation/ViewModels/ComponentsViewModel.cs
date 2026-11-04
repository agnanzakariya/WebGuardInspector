using System.Collections.ObjectModel;
using System.Windows.Input;
using WebGuard.Core.Detection;
using WebGuard.Core.Fixing;
using WebGuard.Core.Updates;
using WebGuard.Presentation.Mvvm;
using WebGuard.Presentation.Services;

namespace WebGuard.Presentation.ViewModels;

/// <summary>One component in Settings → Components.</summary>
public sealed class ComponentRowViewModel : ObservableObject
{
    private ComponentState _state;
    private bool _isUpdating;
    private string _message = string.Empty;

    public ComponentRowViewModel(ComponentState state, Func<ComponentRowViewModel, Task> update)
    {
        _state = state;
        UpdateCommand = new AsyncRelayCommand(() => update(this), () => State.CanUpdate && !IsUpdating);
    }

    public ComponentState State
    {
        get => _state;
        set
        {
            if (!SetProperty(ref _state, value)) return;
            foreach (var n in new[] { nameof(Name), nameof(InstalledText), nameof(LatestText), nameof(SourceText), nameof(StatusText), nameof(Tone), nameof(Note), nameof(HasNote) })
                OnPropertyChanged(n);
            UpdateCommand.RaiseCanExecuteChanged();
        }
    }

    public string Name => State.Name;
    public string InstalledText => State.InstalledVersion is { Length: > 0 } v ? v : "—";
    public string LatestText => State.LatestVersion is { Length: > 0 } v ? v : "unknown";
    public string Note => State.Note ?? string.Empty;
    public bool HasNote => State.Note is { Length: > 0 };

    public string SourceText => State.Source switch
    {
        ComponentSource.Bundled => "Bundled with Azura · GitHub release",
        ComponentSource.Winget => "winget",
        ComponentSource.Pip => "pip (Python)",
        ComponentSource.ClaudeUpdater => "claude update",
        ComponentSource.Manual => "installed manually",
        _ => "not installed",
    };

    public string StatusText => State switch
    {
        { Source: ComponentSource.Missing } => "Not installed",
        { UpdateAvailable: true } => "Update available",
        { LatestVersion: null } => "Unknown",
        _ => "Up to date",
    };

    public StatusTone Tone => State switch
    {
        { Source: ComponentSource.Missing } => StatusTone.Warning,
        { UpdateAvailable: true } => StatusTone.Info,
        { LatestVersion: null } => StatusTone.Neutral,
        _ => StatusTone.Success,
    };

    public bool IsUpdating
    {
        get => _isUpdating;
        set { if (SetProperty(ref _isUpdating, value)) UpdateCommand.RaiseCanExecuteChanged(); }
    }

    public string Message { get => _message; set => SetProperty(ref _message, value); }
    public AsyncRelayCommand UpdateCommand { get; }
}

/// <summary>
/// Settings → Components: installed and latest versions of the security engines and Claude Code, and updating each one
/// the way it was installed (see <see cref="IComponentUpdater"/>). Checked together with the app update check.
/// </summary>
public sealed class ComponentsViewModel : ObservableObject
{
    private readonly IReadOnlyList<ISecurityEngine> _engines;
    private readonly ICodeFixer? _fixer;
    private readonly IComponentUpdater? _updater;
    private readonly EngineCatalogViewModel _catalog;
    private readonly IDialogService? _dialogs;
    private string _status = "Press Check components to look for newer versions.";
    private bool _isBusy;

    public ComponentsViewModel(IReadOnlyList<ISecurityEngine> engines, EngineCatalogViewModel catalog, IComponentUpdater? updater = null,
        ICodeFixer? fixer = null, IDialogService? dialogs = null)
    {
        _engines = engines;
        _catalog = catalog;
        _updater = updater;
        _fixer = fixer;
        _dialogs = dialogs;
        CheckCommand = new AsyncRelayCommand(() => CheckAsync(), () => _updater is not null && !IsBusy, ex => Status = "Check failed: " + ex.Message);
        UpdateAllCommand = new AsyncRelayCommand(UpdateAllAsync, () => !IsBusy && Rows.Any(r => r.State.CanUpdate), ex => Status = "Update failed: " + ex.Message);
    }

    public ObservableCollection<ComponentRowViewModel> Rows { get; } = [];
    public AsyncRelayCommand CheckCommand { get; }
    public AsyncRelayCommand UpdateAllCommand { get; }
    public string Status { get => _status; private set => SetProperty(ref _status, value); }
    public int UpdatesAvailable => Rows.Count(r => r.State.UpdateAvailable);

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (!SetProperty(ref _isBusy, value)) return;
            CheckCommand.RaiseCanExecuteChanged();
            UpdateAllCommand.RaiseCanExecuteChanged();
        }
    }

    /// <summary>Checks every component; returns the ones with a newer version.</summary>
    public async Task<IReadOnlyList<ComponentState>> CheckAsync(CancellationToken cancellationToken = default)
    {
        if (_updater is null || IsBusy) return [];
        IsBusy = true;
        Status = "Checking components…";
        try
        {
            var installed = await FindInstalledAsync(cancellationToken).ConfigureAwait(true);
            var states = await _updater.CheckAsync(installed, cancellationToken).ConfigureAwait(true);
            Rows.Clear();
            foreach (var s in states) Rows.Add(new ComponentRowViewModel(s, UpdateRowAsync));
            var updates = states.Where(s => s.UpdateAvailable).ToArray();
            Status = updates.Length == 0
                ? "All components are up to date."
                : $"{updates.Length} update(s) available: " + string.Join(", ", updates.Select(u => $"{u.Name} {u.InstalledVersion} → {u.LatestVersion}"));
            OnPropertyChanged(nameof(UpdatesAvailable));
            return updates;
        }
        finally
        {
            IsBusy = false;
        }
    }

    /// <summary>
    /// Start-up check (called with the daily app update check). When updates exist, asks whether to open
    /// Settings → Components; returns true when the person said yes.
    /// </summary>
    public async Task<bool> CheckOnStartupAsync(CancellationToken cancellationToken = default)
    {
        var updates = await CheckAsync(cancellationToken).ConfigureAwait(true);
        if (updates.Count == 0 || _dialogs is null) return false;
        var list = string.Join("\n", updates.Select(u => $"•  {u.Name}: {u.InstalledVersion} → {u.LatestVersion}"));
        return _dialogs.Confirm("Component updates available",
            $"Newer versions are available:\n\n{list}\n\nOpen Settings → Components to update them now?");
    }

    private async Task<List<InstalledComponent>> FindInstalledAsync(CancellationToken cancellationToken)
    {
        var list = new List<InstalledComponent>();
        foreach (var engine in _engines.Where(e => e.Info.Id != "malware-hash"))
        {
            var status = await engine.GetStatusAsync(cancellationToken).ConfigureAwait(true);
            list.Add(new InstalledComponent(engine.Info.Id, engine.Info.DisplayName, status.Version, Existing(status.ExecutablePath)));
        }
        if (_fixer is not null)
        {
            var status = await _fixer.GetStatusAsync(cancellationToken).ConfigureAwait(true);
            list.Add(new InstalledComponent("claude-code", "Claude Code", status.Version, Existing(status.ExecutablePath)));
        }
        return list;
    }

    private static string? Existing(string? path) => path is not null && Path.IsPathFullyQualified(path) && File.Exists(path) ? path : null;

    private async Task UpdateRowAsync(ComponentRowViewModel row)
    {
        if (_updater is null) return;
        row.IsUpdating = true;
        IsBusy = true;
        try
        {
            var progress = new Progress<string>(m => row.Message = m);
            row.Message = await _updater.UpdateAsync(row.State, progress, CancellationToken.None).ConfigureAwait(true);
            await _catalog.RefreshAsync().ConfigureAwait(true);
            // Read the version again from the tool itself.
            var installed = (await FindInstalledAsync(CancellationToken.None).ConfigureAwait(true)).FirstOrDefault(c => c.Id == row.State.Id);
            if (installed is not null)
            {
                var fresh = (await _updater.CheckAsync([installed], CancellationToken.None).ConfigureAwait(true)).Single();
                row.State = fresh;
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or HttpRequestException or UnauthorizedAccessException)
        {
            row.Message = ex.Message;
        }
        finally
        {
            row.IsUpdating = false;
            IsBusy = false;
            OnPropertyChanged(nameof(UpdatesAvailable));
            UpdateAllCommand.RaiseCanExecuteChanged();
        }
    }

    private async Task UpdateAllAsync()
    {
        foreach (var row in Rows.Where(r => r.State.CanUpdate).ToArray()) await UpdateRowAsync(row).ConfigureAwait(true);
        Status = UpdatesAvailable == 0 ? "All components are up to date." : "Some updates did not finish; see the messages above.";
    }
}
