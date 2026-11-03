using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.Windows.Input;
using WebGuard.Core.Reporting;
using WebGuard.Core.Scanning;
using WebGuard.Presentation.Formatting;
using WebGuard.Presentation.Mvvm;
using WebGuard.Presentation.Services;

namespace WebGuard.Presentation.ViewModels;

/// <summary>
/// Shared state for the Select Folder → Scan → Investigate workflow.
/// Used by both the Overview and Local Scanner pages so they always show the same session.
/// </summary>
public sealed class ScanWorkspaceViewModel : ObservableObject, IDisposable
{
    public static IReadOnlyList<string> StatusFilters { get; } = ["All", "Hashed", "Skipped", "Errors"];

    private readonly ILocalScanner _scanner;
    private readonly IReportExporter _exporter;
    private readonly IScanHistoryStore _history;
    private readonly SettingsService _settings;
    private readonly IFolderPicker _folderPicker;
    private readonly ISaveFileDialogService _saveDialog;
    private readonly IClipboardService _clipboard;
    private readonly IDialogService _dialogs;
    private readonly List<FileItemViewModel> _allFiles = [];
    private CancellationTokenSource? _cts;
    private ScanReport? _report;
    private string _folderPath;
    private string _searchText = string.Empty;
    private string _statusFilter = "All";
    private bool _isScanning;
    private double _progressPercent;
    private string _progressText = string.Empty;
    private string _currentFile = string.Empty;
    private string _statusMessage = "Ready. Select a local source-code folder to begin.";
    private string _elapsedText = string.Empty;
    private string _filesDeltaText = string.Empty;
    private StatusTone _filesDeltaTone = StatusTone.Neutral;
    private FileItemViewModel? _selectedFile;
    private ObservableCollection<FileItemViewModel> _files = [];
    private IReadOnlyList<InventoryInsight> _insights = [];

    public ScanWorkspaceViewModel(
        ILocalScanner scanner,
        IReportExporter exporter,
        IScanHistoryStore history,
        SettingsService settings,
        IFolderPicker folderPicker,
        ISaveFileDialogService saveDialog,
        IClipboardService clipboard,
        IDialogService dialogs)
    {
        _scanner = scanner;
        _exporter = exporter;
        _history = history;
        _settings = settings;
        _folderPicker = folderPicker;
        _saveDialog = saveDialog;
        _clipboard = clipboard;
        _dialogs = dialogs;
        _folderPath = settings.Current.LastFolder ?? string.Empty;

        BrowseCommand = new RelayCommand(Browse, () => !IsScanning);
        ClearFolderCommand = new RelayCommand(() => FolderPath = string.Empty, () => !IsScanning && FolderPath.Length > 0);
        StartScanCommand = new AsyncRelayCommand(StartScanAsync, () => !IsScanning && IsFolderValid, ReportUnexpected);
        CancelScanCommand = new RelayCommand(() => _cts?.Cancel(), () => IsScanning);
        ExportCommand = new AsyncRelayCommand(ExportAsync, () => !IsScanning && _report is not null, ReportUnexpected);
        CopyHashCommand = new RelayCommand<FileItemViewModel>(CopyHash, f => (f ?? SelectedFile)?.HasHash == true);
        CopyPathCommand = new RelayCommand<FileItemViewModel>(CopyPath, f => (f ?? SelectedFile) is not null);
        ClearSearchCommand = new RelayCommand(() => SearchText = string.Empty);
    }

    public event EventHandler<ScanReport>? ScanCompleted;

    public ICommand BrowseCommand { get; }
    public ICommand ClearFolderCommand { get; }
    public AsyncRelayCommand StartScanCommand { get; }
    public ICommand CancelScanCommand { get; }
    public AsyncRelayCommand ExportCommand { get; }
    public ICommand CopyHashCommand { get; }
    public ICommand CopyPathCommand { get; }
    public ICommand ClearSearchCommand { get; }

    public ScanReport? Report => _report;

    public string FolderPath
    {
        get => _folderPath;
        set
        {
            if (!SetProperty(ref _folderPath, value?.Trim().Trim('"') ?? string.Empty)) return;
            OnPropertyChanged(nameof(IsFolderValid));
            OnPropertyChanged(nameof(FolderHint));
            RaiseStepChanges();
            RefreshCommands();
        }
    }

    public bool IsFolderValid => FolderPath.Length > 0 && System.IO.Directory.Exists(FolderPath);

    public string FolderHint => FolderPath.Length == 0
        ? "Choose a local project folder to scan (Ctrl+O)"
        : IsFolderValid ? "Folder ready. Press Start Scan or F5." : "Folder not found.";

    public bool IsScanning
    {
        get => _isScanning;
        private set
        {
            if (!SetProperty(ref _isScanning, value)) return;
            RaiseStepChanges();
            RefreshCommands();
        }
    }

    public double ProgressPercent { get => _progressPercent; private set => SetProperty(ref _progressPercent, value); }
    public string ProgressText { get => _progressText; private set => SetProperty(ref _progressText, value); }
    public string CurrentFile { get => _currentFile; private set => SetProperty(ref _currentFile, value); }
    public string StatusMessage { get => _statusMessage; private set => SetProperty(ref _statusMessage, value); }
    public string ElapsedText { get => _elapsedText; private set => SetProperty(ref _elapsedText, value); }

    // ---- Step indicator (1 Select Folder → 2 Scan → 3 Investigate) ----
    public bool IsStep1Complete => IsFolderValid;
    public bool IsStep2Active => IsScanning;
    public bool IsStep2Complete => HasReport && !IsScanning;
    public bool IsStep3Active => HasReport && !IsScanning;

    // ---- Results ----
    public bool HasReport => _report is not null;
    public bool HasNoReport => _report is null;
    public ObservableCollection<FileItemViewModel> Files { get => _files; private set => SetProperty(ref _files, value); }
    public IReadOnlyList<InventoryInsight> Insights { get => _insights; private set => SetProperty(ref _insights, value); }

    public FileItemViewModel? SelectedFile
    {
        get => _selectedFile;
        set
        {
            if (!SetProperty(ref _selectedFile, value)) return;
            OnPropertyChanged(nameof(HasSelectedFile));
            RefreshCommands();
        }
    }

    public bool HasSelectedFile => SelectedFile is not null;

    public string SearchText
    {
        get => _searchText;
        set { if (SetProperty(ref _searchText, value ?? string.Empty)) ApplyFilter(); }
    }

    public string StatusFilter
    {
        get => _statusFilter;
        set { if (SetProperty(ref _statusFilter, value ?? "All")) ApplyFilter(); }
    }

    public string InventoryCaption => HasReport
        ? Files.Count == _allFiles.Count
            ? $"{DisplayFormat.Count(_allFiles.Count)} files"
            : $"{DisplayFormat.Count(Files.Count)} of {DisplayFormat.Count(_allFiles.Count)} files"
        : "No scan yet";

    public string TotalFilesText => DisplayFormat.Count(_report?.Statistics.FileCount ?? 0);
    public string TotalSizeText => _report is null ? "Source code, config, and assets" : $"{DisplayFormat.Bytes(_report.Statistics.TotalBytes)} · {DisplayFormat.Count(_report.Statistics.ExcludedDirectoryCount)} folders excluded";
    public string FilesDeltaText { get => _filesDeltaText; private set => SetProperty(ref _filesDeltaText, value); }
    public StatusTone FilesDeltaTone { get => _filesDeltaTone; private set => SetProperty(ref _filesDeltaTone, value); }
    public string HashedFilesText => DisplayFormat.Count(_report?.Statistics.HashedCount ?? 0);
    public string HashedPercentText => _report is null ? string.Empty : DisplayFormat.Percent(_report.Statistics.HashedRatio);
    public string HashedCaption => _report is null
        ? "SHA-256 computed per file"
        : $"{DisplayFormat.Count(_report.Statistics.SkippedCount)} skipped · {DisplayFormat.Count(_report.Statistics.ErrorCount)} errors";
    public int ErrorCount => _report?.Statistics.ErrorCount ?? 0;
    public string LastScanText => _report is null ? "Never" : DisplayFormat.DateTime(_report.FinishedAtUtc);
    public string LastScanCaption => _report is null ? "No scan in this session" : "Completed in " + DisplayFormat.Duration(_report.Duration);

    private void Browse()
    {
        var picked = _folderPicker.PickFolder(IsFolderValid ? FolderPath : _settings.Current.LastFolder);
        if (picked is not null) FolderPath = picked;
    }

    internal async Task StartScanAsync()
    {
        if (IsScanning || !IsFolderValid) return;

        var folder = FolderPath;
        _settings.Update(s => s with { LastFolder = folder });
        _cts = new CancellationTokenSource();
        IsScanning = true;
        ProgressPercent = 0;
        ProgressText = "Discovering files…";
        CurrentFile = string.Empty;
        ElapsedText = string.Empty;
        StatusMessage = "Scanning " + folder;
        var stopwatch = Stopwatch.StartNew();

        try
        {
            var progress = new Progress<ScanProgress>(p =>
            {
                ProgressPercent = p.Percent;
                CurrentFile = p.CurrentFile;
                ElapsedText = DisplayFormat.Duration(stopwatch.Elapsed);
                ProgressText = p.Phase switch
                {
                    ScanPhase.Discovering => "Discovering files…",
                    ScanPhase.Hashing => $"Hashing {DisplayFormat.Count(p.Examined)} / {DisplayFormat.Count(p.Total)} files · {p.Percent.ToString("0", CultureInfo.CurrentCulture)}%",
                    ScanPhase.Analyzing => $"Security engines {p.Examined + 1} / {p.Total} · {p.CurrentFile}",
                    _ => "Finalizing report…",
                };
            });

            var report = await _scanner.ScanAsync(folder, _settings.Current.ToScanOptions(), progress, _cts.Token).ConfigureAwait(true);
            var previous = (await _history.GetRecentAsync(50).ConfigureAwait(true))
                .FirstOrDefault(r => string.Equals(r.RootFolder, report.RootFolder, StringComparison.OrdinalIgnoreCase));
            await _history.AddAsync(report).ConfigureAwait(true);
            LoadReport(report, previous);
            StatusMessage = $"Completed: {DisplayFormat.Count(report.Statistics.FileCount)} files, " +
                            $"{DisplayFormat.Count(report.Statistics.HashedCount)} hashed, {DisplayFormat.Count(report.Statistics.ErrorCount)} errors, " +
                            $"{DisplayFormat.Count(report.Findings.Count)} findings from {report.Engines.Count(e => e.Outcome == "Completed")} engine(s) " +
                            $"in {DisplayFormat.Duration(report.Duration)}.";
            ScanCompleted?.Invoke(this, report);
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Scan canceled. Partial results were discarded.";
            ProgressText = "Canceled";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            StatusMessage = "Scan failed: " + ex.Message;
            _dialogs.ShowError("Scan failed", ex.Message);
        }
        finally
        {
            _cts?.Dispose();
            _cts = null;
            IsScanning = false;
        }
    }

    internal void LoadReport(ScanReport report, ScanReport? previous)
    {
        _report = report;
        _allFiles.Clear();
        _allFiles.AddRange(report.Files.Select(f => new FileItemViewModel(f, report.RootFolder)));
        ProgressPercent = 100;
        ProgressText = "Completed";
        CurrentFile = string.Empty;
        Insights = InventoryInsights.Analyze(report.Files.ToArray());

        if (previous is { Statistics.FileCount: > 0 })
        {
            var delta = (double)(report.Statistics.FileCount - previous.Statistics.FileCount) / previous.Statistics.FileCount;
            FilesDeltaText = delta == 0 ? "No change" : (delta > 0 ? "+" : string.Empty) + delta.ToString("P0", CultureInfo.CurrentCulture);
            FilesDeltaTone = delta > 0 ? StatusTone.Warning : delta < 0 ? StatusTone.Info : StatusTone.Neutral;
        }
        else
        {
            FilesDeltaText = string.Empty;
            FilesDeltaTone = StatusTone.Neutral;
        }

        ApplyFilter();
        SelectedFile = Files.FirstOrDefault();
        foreach (var name in new[]
        {
            nameof(Report), nameof(HasReport), nameof(HasNoReport), nameof(TotalFilesText), nameof(TotalSizeText),
            nameof(HashedFilesText), nameof(HashedPercentText), nameof(HashedCaption), nameof(ErrorCount),
            nameof(LastScanText), nameof(LastScanCaption),
        })
        {
            OnPropertyChanged(name);
        }
        RaiseStepChanges();
        RefreshCommands();
    }

    private void ApplyFilter()
    {
        IEnumerable<FileItemViewModel> query = _allFiles;
        query = StatusFilter switch
        {
            "Hashed" => query.Where(f => f.Status == FileScanStatus.Hashed),
            "Skipped" => query.Where(f => f.Status is FileScanStatus.SkippedSize or FileScanStatus.SkippedLink),
            "Errors" => query.Where(f => f.Status == FileScanStatus.Error),
            _ => query,
        };
        var term = SearchText.Trim();
        if (term.Length > 0)
        {
            query = query.Where(f =>
                f.RelativePath.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                (f.Sha256?.StartsWith(term, StringComparison.OrdinalIgnoreCase) ?? false));
        }

        var selected = SelectedFile;
        Files = new ObservableCollection<FileItemViewModel>(query);
        if (selected is not null && !Files.Contains(selected)) SelectedFile = Files.FirstOrDefault();
        OnPropertyChanged(nameof(InventoryCaption));
    }

    private async Task ExportAsync()
    {
        if (_report is null) return;
        var path = _saveDialog.PickSavePath(
            "Export scan report",
            $"{_exporter.FormatName} files (*{_exporter.FileExtension})|*{_exporter.FileExtension}",
            $"webguard-{_report.StartedAtUtc.ToLocalTime():yyyyMMdd-HHmmss}{_exporter.FileExtension}");
        if (path is null) return;

        try
        {
            var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);
            await using (stream.ConfigureAwait(true))
            {
                await _exporter.ExportAsync(_report, stream, CancellationToken.None).ConfigureAwait(true);
            }
            StatusMessage = "Report exported: " + path;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _dialogs.ShowError("Export failed", ex.Message);
        }
    }

    private void CopyHash(FileItemViewModel? file)
    {
        var target = file ?? SelectedFile;
        if (target?.Sha256 is null) return;
        _clipboard.SetText(target.Sha256);
        StatusMessage = "SHA-256 copied for " + target.FileName;
    }

    private void CopyPath(FileItemViewModel? file)
    {
        var target = file ?? SelectedFile;
        if (target is null) return;
        _clipboard.SetText(target.FullPath);
        StatusMessage = "Path copied: " + target.FullPath;
    }

    private void ReportUnexpected(Exception ex)
    {
        StatusMessage = "Unexpected error: " + ex.Message;
        _dialogs.ShowError("Unexpected error", ex.Message);
    }

    /// <summary>Cancels a running scan (called when the main window closes).</summary>
    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
    }

    private void RaiseStepChanges()
    {
        OnPropertyChanged(nameof(IsStep1Complete));
        OnPropertyChanged(nameof(IsStep2Active));
        OnPropertyChanged(nameof(IsStep2Complete));
        OnPropertyChanged(nameof(IsStep3Active));
    }

    private void RefreshCommands()
    {
        foreach (var command in new object[] { BrowseCommand, ClearFolderCommand, StartScanCommand, CancelScanCommand, ExportCommand, CopyHashCommand, CopyPathCommand })
        {
            (command as IRaiseCanExecuteChanged)?.RaiseCanExecuteChanged();
        }
    }
}
