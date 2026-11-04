using System.Collections.ObjectModel;
using System.Windows.Input;
using WebGuard.Core;
using WebGuard.Core.AI;
using WebGuard.Core.Detection;
using WebGuard.Core.Fixing;
using WebGuard.Core.Knowledge;
using WebGuard.Presentation.Mvvm;
using WebGuard.Presentation.Services;

namespace WebGuard.Presentation.ViewModels;

public enum SetupStep { Welcome, Engines, Privacy, AiAnalyst, Claude, SecondBrain, Preferences, Summary }

/// <summary>Result line of a connection test, styled by tone.</summary>
public sealed record ToneText(string Text, StatusTone Tone);

public sealed class SetupStepItemViewModel(SetupStep step, string title) : ObservableObject
{
    private bool _isCurrent;
    private bool _isDone;

    public SetupStep Step { get; } = step;
    public string Title { get; } = title;
    public int Number => (int)Step + 1;
    public bool IsCurrent { get => _isCurrent; set => SetProperty(ref _isCurrent, value); }
    public bool IsDone { get => _isDone; set => SetProperty(ref _isDone, value); }
}

/// <summary>
/// First-run setup. The app cannot be used until the wizard is finished: every step must be confirmed, and each
/// optional feature (online intelligence, local AI, Claude fixing, Second Brain) needs an explicit "use" or "don't use".
/// Each step's values are saved when the person moves on, so the connection tests see them; the wizard only counts as
/// done (<see cref="AppSettings.SetupCompleted"/>) after Finish, so closing the app half way shows it again.
/// </summary>
public sealed class SetupWizardViewModel : ObservableObject
{
    public const string UseIt = "Use it";
    public const string DontUse = "Don't use";
    public const string OnlineLookups = "Allow online lookups";
    public const string OfflineOnly = "Offline only";

    private readonly SettingsService _settings;
    private readonly IThemeService _theme;
    private readonly IAiSecurityAnalyst? _analyst;
    private readonly ICodeFixer? _fixer;
    private readonly ISecondBrainRepository? _secondBrain;
    private readonly IFolderPicker? _folderPicker;
    private SetupStep _step;
    private string _validationMessage = string.Empty;
    private string? _intelChoice;
    private string _abuseChKey = string.Empty;
    private string? _aiChoice;
    private string _aiEndpoint = string.Empty;
    private string _aiModel = string.Empty;
    private ToneText? _aiResult;
    private string? _claudeChoice;
    private string _claudePath = string.Empty;
    private string _claudeModel = string.Empty;
    private ToneText? _claudeResult;
    private string? _vaultChoice;
    private string _vaultPath = string.Empty;
    private bool _autoRecord;
    private string _themeChoice = nameof(AppTheme.Dark);
    private string _excludedText = string.Empty;
    private int _parallelism;

    public SetupWizardViewModel(SettingsService settings, IThemeService theme, EngineCatalogViewModel engines, IAiSecurityAnalyst? analyst = null,
        ICodeFixer? fixer = null, ISecondBrainRepository? secondBrain = null, IFolderPicker? folderPicker = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        _settings = settings;
        _theme = theme;
        _analyst = analyst;
        _fixer = fixer;
        _secondBrain = secondBrain;
        _folderPicker = folderPicker;
        EngineCatalog = engines;
        Steps =
        [
            new(SetupStep.Welcome, "Welcome"),
            new(SetupStep.Engines, "Security engines"),
            new(SetupStep.Privacy, "Privacy"),
            new(SetupStep.AiAnalyst, "Local AI"),
            new(SetupStep.Claude, "Claude fixing"),
            new(SetupStep.SecondBrain, "Second Brain"),
            new(SetupStep.Preferences, "Preferences"),
            new(SetupStep.Summary, "Finish"),
        ];
        BackCommand = new RelayCommand(Back, () => Step != SetupStep.Welcome);
        NextCommand = new RelayCommand(Next);
        RefreshEnginesCommand = new AsyncRelayCommand(() => EngineCatalog.RefreshAsync());
        TestAiCommand = new AsyncRelayCommand(TestAiAsync, () => _analyst is not null && AiChoice == UseIt, ex => AiResult = new(ex.Message, StatusTone.Danger));
        CheckClaudeCommand = new AsyncRelayCommand(CheckClaudeAsync, () => _fixer is not null && ClaudeChoice == UseIt,
            ex => ClaudeResult = new(ex.Message, StatusTone.Danger));
        BrowseVaultCommand = new RelayCommand(() =>
        {
            if (_folderPicker?.PickFolder(VaultPath.Length > 0 ? VaultPath : null) is { } picked) VaultPath = picked;
        }, () => _folderPicker is not null);
        Reset();
    }

    /// <summary>Raised after Finish saved everything.</summary>
    public event EventHandler? Completed;

    public string AppName => AppInfo.Name;
    public EngineCatalogViewModel EngineCatalog { get; }
    public ObservableCollection<SetupStepItemViewModel> Steps { get; }
    public IReadOnlyList<string> FeatureChoices { get; } = [UseIt, DontUse];
    public IReadOnlyList<string> IntelChoices { get; } = [OnlineLookups, OfflineOnly];
    public IReadOnlyList<string> ThemeChoices { get; } = [nameof(AppTheme.Dark), nameof(AppTheme.Light)];
    public IReadOnlyList<int> ParallelismOptions { get; } = [1, 2, 4, 8];

    public ICommand BackCommand { get; }
    public ICommand NextCommand { get; }
    public AsyncRelayCommand RefreshEnginesCommand { get; }
    public AsyncRelayCommand TestAiCommand { get; }
    public AsyncRelayCommand CheckClaudeCommand { get; }
    public ICommand BrowseVaultCommand { get; }

    public SetupStep Step
    {
        get => _step;
        private set
        {
            if (!SetProperty(ref _step, value)) return;
            foreach (var item in Steps)
            {
                item.IsCurrent = item.Step == value;
                item.IsDone = item.Step < value;
            }
            ValidationMessage = string.Empty;
            foreach (var n in new[] { nameof(StepNumber), nameof(StepTitle), nameof(IsWelcome), nameof(IsEngines), nameof(IsPrivacy),
                         nameof(IsAiAnalyst), nameof(IsClaude), nameof(IsSecondBrain), nameof(IsPreferences), nameof(IsSummary), nameof(NextText),
                         nameof(Summary) })
                OnPropertyChanged(n);
            (BackCommand as IRaiseCanExecuteChanged)?.RaiseCanExecuteChanged();
            if (value == SetupStep.Engines) _ = EngineCatalog.RefreshAsync();
        }
    }

    public int StepNumber => (int)Step + 1;
    public int StepCount => Steps.Count;
    public string StepTitle => Steps[(int)Step].Title;
    public bool IsWelcome => Step == SetupStep.Welcome;
    public bool IsEngines => Step == SetupStep.Engines;
    public bool IsPrivacy => Step == SetupStep.Privacy;
    public bool IsAiAnalyst => Step == SetupStep.AiAnalyst;
    public bool IsClaude => Step == SetupStep.Claude;
    public bool IsSecondBrain => Step == SetupStep.SecondBrain;
    public bool IsPreferences => Step == SetupStep.Preferences;
    public bool IsSummary => Step == SetupStep.Summary;
    public string NextText => Step switch { SetupStep.Welcome => "Start setup", SetupStep.Summary => "Finish", _ => "Next" };
    public string ValidationMessage { get => _validationMessage; private set => SetProperty(ref _validationMessage, value); }

    // ---- Privacy -------------------------------------------------------------------------------------------------

    public string? IntelChoice
    {
        get => _intelChoice;
        set { if (SetProperty(ref _intelChoice, value)) OnPropertyChanged(nameof(UsesOnlineLookups)); }
    }

    public bool UsesOnlineLookups => IntelChoice == OnlineLookups;
    public string AbuseChKey { get => _abuseChKey; set => SetProperty(ref _abuseChKey, value?.Trim() ?? string.Empty); }

    // ---- Local AI ------------------------------------------------------------------------------------------------

    public string? AiChoice
    {
        get => _aiChoice;
        set
        {
            if (!SetProperty(ref _aiChoice, value)) return;
            OnPropertyChanged(nameof(UsesAi));
            TestAiCommand.RaiseCanExecuteChanged();
        }
    }

    public bool UsesAi => AiChoice == UseIt;
    public string AiEndpoint { get => _aiEndpoint; set => SetProperty(ref _aiEndpoint, value?.Trim() ?? string.Empty); }
    public string AiModel { get => _aiModel; set => SetProperty(ref _aiModel, value?.Trim() ?? string.Empty); }
    public ToneText? AiResult
    {
        get => _aiResult;
        private set { if (SetProperty(ref _aiResult, value)) OnPropertyChanged(nameof(HasAiResult)); }
    }

    public bool HasAiResult => AiResult is not null;

    // ---- Claude --------------------------------------------------------------------------------------------------

    public string? ClaudeChoice
    {
        get => _claudeChoice;
        set
        {
            if (!SetProperty(ref _claudeChoice, value)) return;
            OnPropertyChanged(nameof(UsesClaude));
            CheckClaudeCommand.RaiseCanExecuteChanged();
        }
    }

    public bool UsesClaude => ClaudeChoice == UseIt;
    public string ClaudePath { get => _claudePath; set => SetProperty(ref _claudePath, value?.Trim().Trim('"') ?? string.Empty); }
    public string ClaudeModel { get => _claudeModel; set => SetProperty(ref _claudeModel, value?.Trim() ?? string.Empty); }
    public ToneText? ClaudeResult
    {
        get => _claudeResult;
        private set { if (SetProperty(ref _claudeResult, value)) OnPropertyChanged(nameof(HasClaudeResult)); }
    }

    public bool HasClaudeResult => ClaudeResult is not null;

    // ---- Second Brain --------------------------------------------------------------------------------------------

    public string? VaultChoice
    {
        get => _vaultChoice;
        set { if (SetProperty(ref _vaultChoice, value)) OnPropertyChanged(nameof(UsesVault)); }
    }

    public bool UsesVault => VaultChoice == UseIt;
    public string VaultPath { get => _vaultPath; set => SetProperty(ref _vaultPath, value?.Trim().Trim('"') ?? string.Empty); }
    public bool AutoRecord { get => _autoRecord; set => SetProperty(ref _autoRecord, value); }

    // ---- Preferences ---------------------------------------------------------------------------------------------

    public string ThemeChoice
    {
        get => _themeChoice;
        set
        {
            if (value is null || !SetProperty(ref _themeChoice, value)) return;
            _theme.Apply(Enum.Parse<AppTheme>(value));
        }
    }

    public string ExcludedText { get => _excludedText; set => SetProperty(ref _excludedText, value ?? string.Empty); }
    public int Parallelism { get => _parallelism; set => SetProperty(ref _parallelism, value); }

    /// <summary>What will be saved, shown on the last step.</summary>
    public IReadOnlyList<LabeledValue> Summary =>
    [
        new("Security engines", EngineCatalog.Summary),
        new("Online intelligence", UsesOnlineLookups
            ? "On" + (AbuseChKey.Length > 0 ? " · abuse.ch key set" : " · no abuse.ch key (MalwareBazaar/ThreatFox off)")
            : "Off · nothing leaves this PC"),
        new("Local AI analyst", UsesAi ? $"On · {AiEndpoint}{(AiModel.Length > 0 ? " · " + AiModel : string.Empty)}" : "Off"),
        new("Claude fixing", UsesClaude ? "On" + (ClaudeModel.Length > 0 ? " · model " + ClaudeModel : string.Empty) : "Off"),
        new("Second Brain", UsesVault ? VaultPath + (AutoRecord ? " · records automatically" : " · manual") : "Off"),
        new("Preferences", $"{ThemeChoice} theme · {Parallelism} parallel reader(s) · {SplitExcluded().Length} excluded folder names"),
    ];

    /// <summary>Starts again from the first step with the current settings filled in; feature choices must be made again.</summary>
    public void Reset()
    {
        var s = _settings.Current;
        IntelChoice = null;
        AbuseChKey = s.AbuseChAuthKey ?? string.Empty;
        AiChoice = null;
        AiEndpoint = s.AiEndpoint;
        AiModel = s.AiModel ?? string.Empty;
        AiResult = null;
        ClaudeChoice = null;
        ClaudePath = s.ClaudeCliPath ?? string.Empty;
        ClaudeModel = s.ClaudeModel ?? string.Empty;
        ClaudeResult = null;
        VaultChoice = null;
        VaultPath = s.SecondBrainVaultPath ?? string.Empty;
        AutoRecord = s.SecondBrainAutoRecord;
        _themeChoice = s.Theme.ToString();
        OnPropertyChanged(nameof(ThemeChoice));
        ExcludedText = string.Join(Environment.NewLine, s.ExcludedDirectories);
        Parallelism = s.MaxDegreeOfParallelism;
        _step = SetupStep.Engines;
        Step = SetupStep.Welcome;
    }

    private void Back()
    {
        if (Step > SetupStep.Welcome) Step--;
    }

    internal void Next()
    {
        var error = Validate();
        if (error is not null)
        {
            ValidationMessage = error;
            return;
        }
        Commit(Step);
        if (Step == SetupStep.Summary)
        {
            _settings.Update(s => s with { SetupCompleted = true });
            Completed?.Invoke(this, EventArgs.Empty);
            return;
        }
        Step++;
    }

    /// <summary>Null when the current step may be left, else what is missing.</summary>
    internal string? Validate() => Step switch
    {
        SetupStep.Privacy when IntelChoice is null => "Choose whether WebGuard may use online threat intelligence.",
        SetupStep.AiAnalyst when AiChoice is null => "Choose whether to use the local AI analyst.",
        SetupStep.AiAnalyst when UsesAi && !(Uri.TryCreate(AiEndpoint, UriKind.Absolute, out var uri) && uri.IsLoopback) =>
            "The AI endpoint must be a local URL such as " + AppSettings.DefaultAiEndpoint + ".",
        SetupStep.Claude when ClaudeChoice is null => "Choose whether to use Claude for fixing.",
        SetupStep.Claude when UsesClaude && ClaudePath.Length > 0 &&
                              !(Path.IsPathFullyQualified(ClaudePath) && File.Exists(ClaudePath) && ClaudePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) =>
            "The path to claude.exe must be an existing .exe, or leave it empty to detect it automatically.",
        SetupStep.SecondBrain when VaultChoice is null => "Choose whether to use the Second Brain.",
        SetupStep.SecondBrain when UsesVault && (VaultPath.Length == 0 || !Directory.Exists(VaultPath)) =>
            "Pick an existing folder for the Obsidian vault (create it first, or open it in Obsidian).",
        SetupStep.Preferences when Parallelism is < 1 or > 16 => "Choose how many files are read in parallel.",
        _ => null,
    };

    private void Commit(SetupStep step)
    {
        switch (step)
        {
            case SetupStep.Privacy:
                _settings.Update(s => s with { AllowExternalIntelligence = UsesOnlineLookups, AbuseChAuthKey = AbuseChKey.Length == 0 ? null : AbuseChKey });
                break;
            case SetupStep.AiAnalyst:
                _settings.Update(s => s with
                {
                    AiEnabled = UsesAi,
                    AiEndpoint = UsesAi ? AiEndpoint : s.AiEndpoint,
                    AiModel = UsesAi ? (AiModel.Length == 0 ? null : AiModel) : s.AiModel,
                });
                break;
            case SetupStep.Claude:
                _settings.Update(s => s with
                {
                    ClaudeFixEnabled = UsesClaude,
                    ClaudeCliPath = ClaudePath.Length == 0 ? null : ClaudePath,
                    ClaudeModel = ClaudeModel.Length == 0 ? null : ClaudeModel,
                });
                break;
            case SetupStep.SecondBrain:
                _settings.Update(s => s with { SecondBrainVaultPath = UsesVault ? VaultPath : null, SecondBrainAutoRecord = AutoRecord });
                break;
            case SetupStep.Preferences:
                var excluded = SplitExcluded();
                _settings.Update(s => s with
                {
                    Theme = Enum.Parse<AppTheme>(ThemeChoice),
                    ExcludedDirectories = excluded.Length == 0 ? s.ExcludedDirectories : excluded,
                    MaxDegreeOfParallelism = Parallelism,
                });
                break;
        }
    }

    private string[] SplitExcluded() => ExcludedText
        .Split(['\r', '\n', ',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

    private async Task TestAiAsync()
    {
        if (Validate() is { } error)
        {
            AiResult = new(error, StatusTone.Warning);
            return;
        }
        Commit(SetupStep.AiAnalyst);
        AiResult = new("Connecting…", StatusTone.Neutral);
        var status = await _analyst!.GetStatusAsync(CancellationToken.None).ConfigureAwait(true);
        AiResult = Describe(status, "You can continue now and start LM Studio later.");
    }

    private async Task CheckClaudeAsync()
    {
        if (Validate() is { } error)
        {
            ClaudeResult = new(error, StatusTone.Warning);
            return;
        }
        Commit(SetupStep.Claude);
        ClaudeResult = new("Checking Claude Code…", StatusTone.Neutral);
        var status = await _fixer!.GetStatusAsync(CancellationToken.None).ConfigureAwait(true);
        ClaudeResult = Describe(status, "You can continue now and sign in later; the Fixing page has a refresh button.");
    }

    private static ToneText Describe(EngineStatus status, string notReadyHint) => status.Availability == EngineAvailability.Ready
        ? new(status.Message ?? "Ready.", StatusTone.Success)
        : new((status.Message ?? status.Availability.ToString()) + " " + notReadyHint, StatusTone.Warning);

    /// <summary>Vault status line for the Second Brain step (whether the folder exists).</summary>
    public string VaultHint => _secondBrain is null ? string.Empty : "Open this folder in Obsidian with \"Open folder as vault\".";
}
