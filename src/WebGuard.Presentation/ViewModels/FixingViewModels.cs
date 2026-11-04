using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows.Input;
using WebGuard.Core.AI;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Fixing;
using WebGuard.Core.Knowledge;
using WebGuard.Core.Scanning;
using WebGuard.Presentation.Formatting;
using WebGuard.Presentation.Mvvm;
using WebGuard.Presentation.Services;

namespace WebGuard.Presentation.ViewModels;

public enum FixState { NotStarted, Working, Proposed, FalsePositive, CannotFix, Applied, Failed }

/// <summary>One row of the diff view. Kind is Header, Context, Added or Removed. Text is redacted like all evidence.</summary>
public sealed record DiffRowViewModel(string Kind, string OldNumber, string NewNumber, string Prefix, string Text);

/// <summary>A finding on the Fixing page with Claude's proposal and what happened to it.</summary>
public sealed class FixItemViewModel(SecurityFinding finding) : ObservableObject
{
    private SecurityFinding _finding = finding;
    private FixState _state;
    private FixProposal? _proposal;
    private PatchResult? _patch;
    private AppliedFix? _applied;
    private string _message = string.Empty;

    public SecurityFinding Finding
    {
        get => _finding;
        set { if (SetProperty(ref _finding, value)) OnPropertyChanged(nameof(StatusText)); }
    }

    public string Title => _finding.Title;
    public string Location => _finding.Location.ToString();
    public string File => Path.GetFileName(_finding.Location.RelativePath);
    public Severity Severity => _finding.Severity;
    public string SeverityText => _finding.Severity.ToString();
    public string StatusText => _finding.Status.ToString();
    public string Engine => _finding.EngineId;
    public string RuleId => _finding.RuleId;

    public FixState State
    {
        get => _state;
        set
        {
            if (!SetProperty(ref _state, value)) return;
            foreach (var n in new[] { nameof(StateText), nameof(Tone), nameof(CanApply), nameof(CanUndo), nameof(IsFalsePositive), nameof(IsWorking) })
                OnPropertyChanged(n);
        }
    }

    public bool IsWorking => State == FixState.Working;

    public string StateText => State switch
    {
        FixState.NotStarted => "Not started",
        FixState.Working => "Asking Claude…",
        FixState.Proposed => "Fix ready to review",
        FixState.FalsePositive => "Likely false positive",
        FixState.CannotFix => "Needs manual action",
        FixState.Applied => "Applied",
        _ => "Failed",
    };

    public StatusTone Tone => State switch
    {
        FixState.Proposed => StatusTone.Info,
        FixState.Applied => StatusTone.Success,
        FixState.FalsePositive or FixState.CannotFix => StatusTone.Warning,
        FixState.Failed => StatusTone.Danger,
        _ => StatusTone.Neutral,
    };

    public FixProposal? Proposal
    {
        get => _proposal;
        set
        {
            if (!SetProperty(ref _proposal, value)) return;
            foreach (var n in new[] { nameof(HasProposal), nameof(Explanation), nameof(Footer) }) OnPropertyChanged(n);
        }
    }

    public bool HasProposal => Proposal is not null;
    public string Explanation => Proposal?.Explanation ?? string.Empty;
    public string Footer => Proposal is null ? string.Empty
        : $"{Proposal.Model} · {Proposal.Confidence} confidence · {DisplayFormat.DateTime(Proposal.CreatedAtUtc)}";

    public PatchResult? Patch
    {
        get => _patch;
        set
        {
            if (!SetProperty(ref _patch, value)) return;
            DiffRows = BuildRows(value, _finding.Location.RelativePath);
            foreach (var n in new[] { nameof(DiffRows), nameof(HasDiff), nameof(DiffSummary), nameof(CanApply) }) OnPropertyChanged(n);
        }
    }

    public IReadOnlyList<DiffRowViewModel> DiffRows { get; private set; } = [];
    public bool HasDiff => DiffRows.Count > 0;
    public string DiffSummary => Patch is { Succeeded: true } p
        ? string.Create(CultureInfo.InvariantCulture, $"+{p.AddedLines} −{p.RemovedLines} in {_finding.Location.RelativePath}")
        : string.Empty;

    public AppliedFix? Applied
    {
        get => _applied;
        set { if (SetProperty(ref _applied, value)) OnPropertyChanged(nameof(CanUndo)); }
    }

    public string Message { get => _message; set => SetProperty(ref _message, value); }

    public bool CanApply => State == FixState.Proposed && Patch is { Succeeded: true };
    public bool CanUndo => State == FixState.Applied && Applied is not null;
    public bool IsFalsePositive => State == FixState.FalsePositive;

    private static DiffRowViewModel[] BuildRows(PatchResult? patch, string relativePath)
    {
        if (patch is not { Succeeded: true }) return [];
        var rows = new List<DiffRowViewModel>();
        foreach (var hunk in patch.Hunks)
        {
            rows.Add(new DiffRowViewModel("Header", "", "", "", string.Create(CultureInfo.InvariantCulture, $"@@ line {hunk.OldStart} → {hunk.NewStart} @@")));
            foreach (var line in hunk.Lines)
            {
                rows.Add(new DiffRowViewModel(
                    line.Kind.ToString(),
                    line.OldLine?.ToString(CultureInfo.InvariantCulture) ?? "",
                    line.NewLine?.ToString(CultureInfo.InvariantCulture) ?? "",
                    line.Kind switch { DiffKind.Added => "+", DiffKind.Removed => "−", _ => " " },
                    SourceRedactor.Redact(line.Text, relativePath)));
            }
        }
        return [.. rows];
    }
}

/// <summary>
/// Fixing page: asks Claude for a fix per finding, shows the proposed change as a diff, and writes it only when the
/// person clicks Apply (with a backup and Undo). A "false positive" answer is only a suggestion until confirmed.
/// </summary>
public sealed class FixingViewModel : PageViewModel, IDisposable
{
    private static readonly ValidationStatus[] ClosedStatuses = [ValidationStatus.FalsePositive, ValidationStatus.AcceptedRisk, ValidationStatus.Fixed];
    private readonly FindingsViewModel _findings;
    private readonly ICodeFixer? _fixer;
    private readonly FixApplier _applier;
    private readonly ISecondBrainRepository? _secondBrain;
    private readonly SettingsService? _settings;
    private FixItemViewModel? _selected;
    private CancellationTokenSource? _cts;
    private bool _isWorking;
    private string _progressText = string.Empty;
    private string _message = string.Empty;
    private string _fixerStatusText = "Checking Claude Code…";
    private StatusTone _fixerTone = StatusTone.Neutral;
    private bool _isFixerReady;

    public FixingViewModel(FindingsViewModel findings, ICodeFixer? fixer, FixApplier applier, ISecondBrainRepository? secondBrain = null,
        SettingsService? settings = null)
    {
        ArgumentNullException.ThrowIfNull(findings);
        _findings = findings;
        _fixer = fixer;
        _applier = applier;
        _secondBrain = secondBrain;
        _settings = settings;
        FixSelectedCommand = new AsyncRelayCommand(FixSelectedAsync, () => CanAsk && SelectedItem is { IsWorking: false },
            ex => Message = "Fixing failed: " + ex.Message);
        FixAllCommand = new AsyncRelayCommand(FixAllAsync, () => CanAsk && Items.Any(IsOpen), ex => Message = "Fixing failed: " + ex.Message);
        CancelCommand = new RelayCommand(() => _cts?.Cancel(), () => IsWorking);
        ApplyCommand = new AsyncRelayCommand(ApplySelectedAsync, () => !IsWorking && SelectedItem?.CanApply == true, ex => Message = "Apply failed: " + ex.Message);
        UndoCommand = new AsyncRelayCommand(UndoSelectedAsync, () => !IsWorking && SelectedItem?.CanUndo == true, ex => Message = "Undo failed: " + ex.Message);
        ConfirmFalsePositiveCommand = new AsyncRelayCommand(ConfirmFalsePositiveAsync,
            () => SelectedItem is { IsFalsePositive: true } item && item.Finding.Status != ValidationStatus.FalsePositive);
        RefreshStatusCommand = new AsyncRelayCommand(() => RefreshAsync());

        findings.ReportLoaded += (_, report) => Load(report);
        findings.StatusRecorded += (_, finding) =>
        {
            foreach (var item in Items.Where(i => i.Finding.Fingerprint == finding.Fingerprint)) item.Finding = item.Finding with { Status = finding.Status };
            RaiseCommands();
        };
    }

    public override PageKey Key => PageKey.Fixing;
    public override string Title => "Fixing";
    public override string Subtitle => "Claude proposes the change · you review the diff · Apply keeps a backup";

    public ObservableCollection<FixItemViewModel> Items { get; } = [];
    public bool HasItems => Items.Count > 0;
    public bool HasNoItems => Items.Count == 0;
    public string EmptyText => _findings.Report is null ? "Run a scan first; its findings appear here." : "This scan has no findings to fix.";

    public AsyncRelayCommand FixSelectedCommand { get; }
    public AsyncRelayCommand FixAllCommand { get; }
    public ICommand CancelCommand { get; }
    public AsyncRelayCommand ApplyCommand { get; }
    public AsyncRelayCommand UndoCommand { get; }
    public AsyncRelayCommand ConfirmFalsePositiveCommand { get; }
    public AsyncRelayCommand RefreshStatusCommand { get; }

    public string FixerStatusText { get => _fixerStatusText; private set => SetProperty(ref _fixerStatusText, value); }
    public StatusTone Tone { get => _fixerTone; private set => SetProperty(ref _fixerTone, value); }

    public bool IsFixerReady
    {
        get => _isFixerReady;
        private set { if (SetProperty(ref _isFixerReady, value)) RaiseCommands(); }
    }

    public bool IsWorking
    {
        get => _isWorking;
        private set { if (SetProperty(ref _isWorking, value)) RaiseCommands(); }
    }

    public string ProgressText { get => _progressText; private set => SetProperty(ref _progressText, value); }
    public string Message { get => _message; private set => SetProperty(ref _message, value); }

    public FixItemViewModel? SelectedItem
    {
        get => _selected;
        set
        {
            if (!SetProperty(ref _selected, value)) return;
            OnPropertyChanged(nameof(HasSelectedItem));
            RaiseCommands();
        }
    }

    public bool HasSelectedItem => SelectedItem is not null;

    private bool CanAsk => _fixer is not null && IsFixerReady && !IsWorking && _findings.Report is not null;

    /// <summary>Open = worth asking Claude: not yet answered (or failed) and not already closed by a verdict.</summary>
    private static bool IsOpen(FixItemViewModel item) =>
        item.State is FixState.NotStarted or FixState.Failed && !ClosedStatuses.Contains(item.Finding.Status);

    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        if (_fixer is null)
        {
            (FixerStatusText, Tone, IsFixerReady) = ("No AI fixer is configured.", StatusTone.Warning, false);
            return;
        }
        var status = await _fixer.GetStatusAsync(cancellationToken).ConfigureAwait(true);
        FixerStatusText = status.Message ?? status.Availability.ToString();
        Tone = status.Availability switch
        {
            EngineAvailability.Ready => StatusTone.Success,
            EngineAvailability.Disabled => StatusTone.Neutral,
            EngineAvailability.Error => StatusTone.Danger,
            _ => StatusTone.Warning,
        };
        IsFixerReady = status.Availability == EngineAvailability.Ready;
    }

    public void Load(ScanReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        _cts?.Cancel();
        Items.Clear();
        foreach (var f in _findings.AllFindings.OrderByDescending(f => f.Severity)) Items.Add(new FixItemViewModel(f));
        SelectedItem = Items.FirstOrDefault();
        Message = string.Empty;
        foreach (var n in new[] { nameof(HasItems), nameof(HasNoItems), nameof(EmptyText) }) OnPropertyChanged(n);
        RaiseCommands();
    }

    internal async Task FixSelectedAsync()
    {
        if (SelectedItem is not { } item) return;
        await RunAsync([item]).ConfigureAwait(true);
    }

    internal async Task FixAllAsync() => await RunAsync(Items.Where(IsOpen).ToArray()).ConfigureAwait(true);

    private async Task RunAsync(FixItemViewModel[] batch)
    {
        if (_fixer is null || _findings.Report is not { } report || batch.Length == 0 || IsWorking) return;
        using var cts = new CancellationTokenSource();
        _cts = cts;
        IsWorking = true;
        Message = string.Empty;
        var scope = new ProjectScope(report.RootFolder);
        var done = 0;
        try
        {
            foreach (var item in batch)
            {
                cts.Token.ThrowIfCancellationRequested();
                ProgressText = batch.Length == 1
                    ? "Asking Claude… this usually takes 20–90 seconds."
                    : string.Create(CultureInfo.InvariantCulture, $"Asking Claude about finding {done + 1} of {batch.Length}…");
                await ProposeAsync(scope, item, cts.Token).ConfigureAwait(true);
                done++;
            }
            var counts = batch.GroupBy(i => i.State).ToDictionary(g => g.Key, g => g.Count());
            int Count(FixState s) => counts.TryGetValue(s, out var c) ? c : 0;
            Message = string.Create(CultureInfo.InvariantCulture,
                $"{Count(FixState.Proposed)} fix(es) to review, {Count(FixState.FalsePositive)} likely false positive(s), " +
                $"{Count(FixState.CannotFix)} need manual action, {Count(FixState.Failed)} failed.");
        }
        catch (OperationCanceledException)
        {
            Message = string.Create(CultureInfo.InvariantCulture, $"Canceled after {done} of {batch.Length}.");
        }
        finally
        {
            foreach (var item in batch.Where(i => i.State == FixState.Working)) item.State = FixState.NotStarted;
            _cts = null;
            ProgressText = string.Empty;
            IsWorking = false;
        }
    }

    private async Task ProposeAsync(ProjectScope scope, FixItemViewModel item, CancellationToken cancellationToken)
    {
        var finding = item.Finding;
        item.Proposal = null;
        item.Patch = null;
        if (!FixRequestBuilder.TryBuild(scope, finding, _findings.AllFindings, out var request, out var error))
        {
            item.State = FixState.CannotFix;
            item.Message = error;
            return;
        }

        item.State = FixState.Working;
        item.Message = string.Empty;
        FixProposal proposal;
        try
        {
            proposal = await _fixer!.ProposeAsync(request, cancellationToken).ConfigureAwait(true);
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or System.ComponentModel.Win32Exception)
        {
            item.State = FixState.Failed;
            item.Message = ex.Message;
            return;
        }

        item.Proposal = proposal;
        switch (proposal.Verdict)
        {
            case FixVerdict.FalsePositive:
                item.State = FixState.FalsePositive;
                item.Message = "Claude thinks this is a false positive. Confirm to record it in the Second Brain, or ignore the suggestion.";
                break;
            case FixVerdict.CannotFix:
                item.State = FixState.CannotFix;
                item.Message = "Claude could not fix this inside the file; see the explanation.";
                break;
            default:
                if (!SourceFile.TryRead(scope, finding.Location.RelativePath, out var file, out error))
                {
                    item.State = FixState.Failed;
                    item.Message = error;
                    break;
                }
                var patch = FixPatcher.Apply(file.Text, proposal.Edits);
                item.Patch = patch;
                item.State = patch.Succeeded ? FixState.Proposed : FixState.Failed;
                item.Message = patch.Succeeded
                    ? "Review the change below, then Apply. A backup is kept and Undo restores it."
                    : "Claude's edits did not match the file: " + string.Join(" ", patch.Errors) + " Try again.";
                break;
        }
        await RememberAsync(finding, proposal, item.Patch).ConfigureAwait(true);
    }

    private async Task ApplySelectedAsync()
    {
        if (SelectedItem is not { Proposal: { } proposal } item || _findings.Report is not { } report) return;
        var finding = item.Finding;
        var (fix, patch) = _applier.Apply(new ProjectScope(report.RootFolder), finding.Location.RelativePath, proposal.Edits,
            $"{finding.Title} ({finding.EngineId} {finding.RuleId}, {finding.Severity})");
        item.Applied = fix;
        item.Patch = patch;
        item.State = FixState.Applied;
        var wreck = fix.WreckPath is null ? string.Empty : Path.GetRelativePath(report.RootFolder, fix.WreckPath);
        item.Message = $"Applied. The vulnerable version is commented out in {wreck} (not scanned; do not deploy the wreck folder). " +
                       "Scan again to confirm the finding is gone.";
        await _findings.SetStatusAsync(item.Finding, ValidationStatus.Fixed,
            $"Fix proposed by {proposal.Model} and applied after review. Old version: {wreck}. Backup: {fix.BackupPath}").ConfigureAwait(true);
        RaiseCommands();
    }

    private async Task UndoSelectedAsync()
    {
        if (SelectedItem is not { Applied: { } fix } item) return;
        FixApplier.Undo(fix);
        item.Applied = null;
        item.State = FixState.Proposed;
        item.Message = "Undone; the original file is back and its wreck copy was removed. The proposal can be applied again.";
        await _findings.SetStatusAsync(item.Finding, ValidationStatus.NeedsReview, "AI fix undone.").ConfigureAwait(true);
        RaiseCommands();
    }

    private async Task ConfirmFalsePositiveAsync()
    {
        if (SelectedItem is not { Proposal: { } proposal } item) return;
        var ok = await _findings.SetStatusAsync(item.Finding, ValidationStatus.FalsePositive,
            $"Confirmed after {proposal.Model} judged it a false positive: {proposal.Explanation}").ConfigureAwait(true);
        item.Message = ok ? "Recorded as FalsePositive in the Second Brain; later scans keep this verdict." : _findings.ValidationMessage;
        RaiseCommands();
    }

    /// <summary>Stores the proposal in the finding's note as an unverified AI analysis (diff redacted).</summary>
    private async Task RememberAsync(SecurityFinding finding, FixProposal proposal, PatchResult? patch)
    {
        if (_secondBrain is null || _settings?.Current.SecondBrainAutoRecord != true) return;
        try
        {
            if ((await _secondBrain.GetStatusAsync(CancellationToken.None).ConfigureAwait(true)).Availability != EngineAvailability.Ready) return;
            var verdict = proposal.Verdict switch
            {
                FixVerdict.FalsePositive => "Fix request: likely false positive.",
                FixVerdict.CannotFix => "Fix request: needs manual action.",
                _ => "Fix request: code change proposed.",
            };
            var diff = patch is { Succeeded: true }
                ? SourceRedactor.Redact(FixPatcher.ToUnifiedText(finding.Location.RelativePath, patch.Hunks), finding.Location.RelativePath)
                : null;
            await _secondBrain.SaveAnalysisAsync(finding, new AiAnalysis(finding.Id, proposal.Model, verdict, proposal.Explanation, diff,
                proposal.Confidence, IsVerified: false, proposal.CreatedAtUtc), CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            // The proposal is still shown; only the note was not updated.
        }
    }

    private void RaiseCommands()
    {
        FixSelectedCommand.RaiseCanExecuteChanged();
        FixAllCommand.RaiseCanExecuteChanged();
        (CancelCommand as IRaiseCanExecuteChanged)?.RaiseCanExecuteChanged();
        ApplyCommand.RaiseCanExecuteChanged();
        UndoCommand.RaiseCanExecuteChanged();
        ConfirmFalsePositiveCommand.RaiseCanExecuteChanged();
    }

    /// <summary>Cancels a running request (called when the main window closes).</summary>
    public void Dispose() => _cts?.Cancel();
}
