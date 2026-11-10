using System.Collections.ObjectModel;
using System.Globalization;
using WebGuard.Core.Findings;
using WebGuard.Core.Reporting;
using WebGuard.Core.Scanning;
using WebGuard.Presentation.Formatting;
using WebGuard.Presentation.Mvvm;
using WebGuard.Presentation.Services;

namespace WebGuard.Presentation.ViewModels;

/// <summary>A titled part of an activity's full result (AI analysis text, fix explanation, diff, command).</summary>
public sealed record ActivitySectionViewModel(string Title, string Text, bool IsCode)
{
    public bool IsText => !IsCode;
}

/// <summary>One row of the session timeline; its full result can be expanded.</summary>
public sealed class SessionActivityRowViewModel : ObservableObject
{
    private bool _isExpanded;

    public SessionActivityRowViewModel(SessionActivity activity)
    {
        Activity = activity;
        Sections = (activity.Sections ?? [])
            .Select(s => new ActivitySectionViewModel(s.Title, s.Text, s.Style != ActivitySectionStyle.Text))
            .ToArray();
        ToggleCommand = new RelayCommand(() => IsExpanded = !IsExpanded, () => HasSections);
    }

    public SessionActivity Activity { get; }
    public IReadOnlyList<ActivitySectionViewModel> Sections { get; }
    public bool HasSections => Sections.Count > 0;
    public System.Windows.Input.ICommand ToggleCommand { get; }

    public bool IsExpanded
    {
        get => _isExpanded;
        set
        {
            if (SetProperty(ref _isExpanded, value)) OnPropertyChanged(nameof(ToggleText));
        }
    }

    public string ToggleText => IsExpanded ? "Hide details" : "Show details";
    public string TimeText => DisplayFormat.DateTime(Activity.AtUtc);
    public string KindText => Activity.Kind switch
    {
        SessionActivityKind.AiAnalysis => "AI analysis",
        SessionActivityKind.FixProposed => "Fix proposal",
        SessionActivityKind.FixApplied => "Fix applied",
        SessionActivityKind.FixUndone => "Fix undone",
        SessionActivityKind.ReportExported => "Export",
        _ => Activity.Kind.ToString(),
    };

    public StatusTone Tone => Activity.Kind switch
    {
        SessionActivityKind.FixApplied => StatusTone.Success,
        SessionActivityKind.FixUndone => StatusTone.Warning,
        SessionActivityKind.Scan => StatusTone.Info,
        _ => StatusTone.Neutral,
    };

    public string Summary => Activity.Summary;
    public string Note => string.Join(" · ", new[] { Activity.Location, Activity.Detail }.Where(s => !string.IsNullOrWhiteSpace(s)));
    public bool HasNote => Note.Length > 0;
}

/// <summary>Résumé of one session: what was scanned, what was found, and what was done about it.</summary>
public sealed class SessionDetailViewModel(ScanReport report, IReadOnlyList<SessionActivity> activities)
{
    private readonly SeveritySummary _severity = SeveritySummary.From(report.Findings);
    private readonly SessionActivitySummary _done = SessionActivitySummary.From(activities);

    public ScanReport Report { get; } = report;
    public IReadOnlyList<SessionActivity> Activities { get; } = activities;
    public string Folder => Report.RootFolder;
    public string WhenText => $"{DisplayFormat.DateTime(Report.StartedAtUtc)} · {DisplayFormat.Duration(Report.Duration)} · {Report.MachineName} · Azura {Report.ToolVersion}";

    public string ResultText => Report.Findings.Count > 0
        ? $"{Report.Findings.Count} finding(s)"
        : Report.Engines.Any(e => e.Outcome == "Completed") ? "Clean" : "Not analysed";

    public StatusTone Tone => Report.Findings.Count > 0
        ? (_severity.Critical + _severity.High > 0 ? StatusTone.Danger : StatusTone.Warning)
        : Report.Engines.Any(e => e.Outcome == "Completed") ? StatusTone.Success : StatusTone.Neutral;

    public string FilesText => DisplayFormat.Count(Report.Statistics.FileCount);
    public string CriticalText => DisplayFormat.Count(_severity.Critical);
    public string HighText => DisplayFormat.Count(_severity.High);
    public string MediumText => DisplayFormat.Count(_severity.Medium);
    public string LowText => DisplayFormat.Count(_severity.Low + _severity.Info);
    public string EnginesText => $"{Report.Engines.Count(e => e.Outcome == "Completed")} of {Report.Engines.Count} engines completed: " +
                                 string.Join(", ", Report.Engines.Where(e => e.Outcome == "Completed").Select(e => $"{e.DisplayName} ({e.FindingCount})"));

    public string StatusText => Report.Findings.Count == 0
        ? "No findings."
        : "Finding status: " + string.Join(", ", Report.Findings.GroupBy(f => f.Status).OrderBy(g => g.Key).Select(g => $"{g.Count()} {g.Key}"));

    public string ActivityText => string.Create(CultureInfo.CurrentCulture,
        $"{_done.Verdicts} verdict(s) · {_done.AiAnalyses} AI analysis(es) · {_done.FixesProposed} fix request(s) · " +
        $"{_done.FixesApplied} applied · {_done.FixesUndone} undone · {_done.Exports} export(s)");

    public IReadOnlyList<SessionActivityRowViewModel> Timeline { get; } =
        activities.Select((a, i) => (a, i)).OrderByDescending(x => x.a.AtUtc).ThenByDescending(x => x.i)
            .Select(x => new SessionActivityRowViewModel(x.a)).ToArray();

    public bool HasTimeline => Timeline.Count > 0;
}

/// <summary>
/// Scan History: every scan session (kept across restarts) and, for the selected one, a résumé of the scan and of the
/// work done on its findings, with export to PDF or JSON.
/// </summary>
public sealed class ScanHistoryViewModel : PageViewModel
{
    private readonly IScanHistoryStore _store;
    private readonly ISaveFileDialogService? _saveDialog;
    private readonly IDialogService? _dialogs;
    private readonly IExternalLauncher? _launcher;
    private readonly ISessionReportExporter? _pdf;
    private readonly IReportExporter? _json;
    private ScanHistoryRowViewModel? _selected;
    private SessionDetailViewModel? _detail;
    private string _message = string.Empty;
    private string? _lastExport;

    public ScanHistoryViewModel(IScanHistoryStore store, SessionActivityLog? activityLog = null, ISaveFileDialogService? saveDialog = null,
        IDialogService? dialogs = null, IExternalLauncher? launcher = null, ISessionReportExporter? pdf = null, IReportExporter? json = null)
    {
        _store = store;
        _saveDialog = saveDialog;
        _dialogs = dialogs;
        _launcher = launcher;
        _pdf = pdf;
        _json = json;
        ExportPdfCommand = new AsyncRelayCommand(() => ExportAsync(pdf: true), () => _detail is not null && _pdf is not null && _saveDialog is not null);
        ExportJsonCommand = new AsyncRelayCommand(() => ExportAsync(pdf: false), () => _detail is not null && _json is not null && _saveDialog is not null);
        OpenExportCommand = new RelayCommand(() =>
        {
            if (_lastExport is not null) _launcher?.Open(new Uri(_lastExport));
        }, () => _lastExport is not null && _launcher is not null);
        if (activityLog is not null)
        {
            activityLog.Recorded += async (_, scanId) =>
            {
                if (_selected?.Report.ScanId == scanId) await LoadDetailAsync().ConfigureAwait(true);
            };
        }
    }

    public override PageKey Key => PageKey.ScanHistory;
    public override string Title => "Scan History";
    public override string Subtitle => "Every scan and fixing session, kept across restarts · select one for its résumé";
    public ObservableCollection<ScanHistoryRowViewModel> Items { get; } = [];
    public bool HasItems => Items.Count > 0;
    public bool HasNoItems => Items.Count == 0;
    public AsyncRelayCommand ExportPdfCommand { get; }
    public AsyncRelayCommand ExportJsonCommand { get; }
    public System.Windows.Input.ICommand OpenExportCommand { get; }

    public ScanHistoryRowViewModel? Selected
    {
        get => _selected;
        set
        {
            if (!SetProperty(ref _selected, value)) return;
            Message = string.Empty;
            _ = LoadDetailAsync();
        }
    }

    public SessionDetailViewModel? Detail
    {
        get => _detail;
        private set
        {
            if (!SetProperty(ref _detail, value)) return;
            OnPropertyChanged(nameof(HasDetail));
            ExportPdfCommand.RaiseCanExecuteChanged();
            ExportJsonCommand.RaiseCanExecuteChanged();
        }
    }

    public bool HasDetail => Detail is not null;

    /// <summary>A report was exported in this run, so "Open the exported file" is shown.</summary>
    public bool HasExport => _lastExport is not null;
    public string Message { get => _message; private set => SetProperty(ref _message, value); }

    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        var selectedId = _selected?.Report.ScanId;
        Items.Clear();
        foreach (var r in await _store.GetRecentAsync(200, cancellationToken).ConfigureAwait(true))
            Items.Add(new ScanHistoryRowViewModel(r));
        OnPropertyChanged(nameof(HasItems));
        OnPropertyChanged(nameof(HasNoItems));
        Selected = Items.FirstOrDefault(i => i.Report.ScanId == selectedId) ?? Items.FirstOrDefault();
        await LoadDetailAsync().ConfigureAwait(true);
    }

    internal async Task LoadDetailAsync()
    {
        if (_selected is not { } row)
        {
            Detail = null;
            return;
        }
        var activities = await _store.GetActivitiesAsync(row.Report.ScanId).ConfigureAwait(true);
        if (_selected == row) Detail = new SessionDetailViewModel(row.Report, activities);
    }

    /// <summary>Writes the selected session as PDF (with its activities) or JSON (the scan report) and records the export.</summary>
    internal async Task ExportAsync(bool pdf, string? path = null)
    {
        if (Detail is not { } detail) return;
        var (name, extension) = pdf ? (_pdf!.FormatName, _pdf.FileExtension) : (_json!.FormatName, _json.FileExtension);
        var project = Path.GetFileName(detail.Folder.TrimEnd('\\', '/'));
        path ??= _saveDialog?.PickSavePath($"Export session report ({name})", $"{name} files (*{extension})|*{extension}",
            $"azura-{project}-{detail.Report.StartedAtUtc.ToLocalTime():yyyyMMdd-HHmmss}{extension}");
        if (path is null) return;
        try
        {
            var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);
            await using (stream.ConfigureAwait(true))
            {
                if (pdf) await _pdf!.ExportAsync(detail.Report, detail.Activities, stream, CancellationToken.None).ConfigureAwait(true);
                else await _json!.ExportAsync(detail.Report, stream, CancellationToken.None).ConfigureAwait(true);
            }
            _lastExport = path;
            OnPropertyChanged(nameof(HasExport));
            (OpenExportCommand as IRaiseCanExecuteChanged)?.RaiseCanExecuteChanged();
            Message = $"{name} report saved: {path}";
            await _store.AppendActivityAsync(detail.Report.ScanId,
                new SessionActivity(DateTimeOffset.UtcNow, SessionActivityKind.ReportExported, $"{name} report exported from Scan History", null, path)).ConfigureAwait(true);
            await LoadDetailAsync().ConfigureAwait(true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Message = "Export failed: " + ex.Message;
            _dialogs?.ShowError("Export failed", ex.Message);
        }
    }
}
