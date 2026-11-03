using System.Text.Json;
using System.Text.Json.Serialization;
using WebGuard.Core.Detection;
using WebGuard.Core.Scanning;

namespace WebGuard.Presentation.Services;

public sealed record AppSettings
{
    public AppTheme Theme { get; init; } = AppTheme.Dark;
    public string? LastFolder { get; init; }
    public IReadOnlyList<string> ExcludedDirectories { get; init; } = ScanOptions.DefaultExcludedDirectories;
    public int MaxHashMegabytes { get; init; } = (int)(ScanOptions.DefaultMaxHashBytes / (1024 * 1024));
    public int MaxDegreeOfParallelism { get; init; } = ScanOptions.Default.MaxDegreeOfParallelism;

    /// <summary>Absolute paths to engine executables keyed by engine id. Empty = auto-detect an installed .exe.</summary>
    public IReadOnlyDictionary<string, string> EngineExecutables { get; init; } = new Dictionary<string, string>();

    /// <summary>Optional rule files/folders per engine (absolute paths). Empty = bundled rules.</summary>
    public IReadOnlyDictionary<string, string[]> EngineRulePaths { get; init; } = new Dictionary<string, string[]>();

    /// <summary>Engine ids switched off by the user.</summary>
    public IReadOnlyList<string> DisabledEngines { get; init; } = [];

    /// <summary>External threat-intelligence lookups are opt-in. Never sends source code.</summary>
    public bool AllowExternalIntelligence { get; init; }

    /// <summary>abuse.ch Auth-Key for MalwareBazaar hash lookups, stored in the per-user settings file.</summary>
    public string? AbuseChAuthKey { get; init; }

    /// <summary>Engines that send data off the machine and therefore also require <see cref="AllowExternalIntelligence"/>.</summary>
    public static IReadOnlyCollection<string> NetworkEngines { get; } = ["osv-scanner"];

    public ScanOptions ToScanOptions() => new ScanOptions
    {
        ExcludedDirectories = ExcludedDirectories,
        MaxHashBytes = Math.Max(1, MaxHashMegabytes) * 1024L * 1024L,
        MaxDegreeOfParallelism = MaxDegreeOfParallelism,
    }.Normalize();

    public ExternalToolOptions ToolOptions(string engineId)
    {
        var path = EngineExecutables.TryGetValue(engineId, out var p) && !string.IsNullOrWhiteSpace(p) ? p : null;
        var rules = EngineRulePaths.TryGetValue(engineId, out var r) ? r : [];
        if (DisabledEngines.Contains(engineId, StringComparer.OrdinalIgnoreCase))
            return new ExternalToolOptions(engineId, path, false, rules, "Disabled in Settings.");
        if (!AllowExternalIntelligence && NetworkEngines.Contains(engineId, StringComparer.OrdinalIgnoreCase))
            return new ExternalToolOptions(engineId, path, false, rules,
                "Sends package names/versions to OSV.dev. Allow external lookups in Settings → Privacy to enable.");
        return new ExternalToolOptions(engineId, path, true, rules);
    }
}

public interface ISettingsStore
{
    AppSettings Load();
    void Save(AppSettings settings);
}

/// <summary>Stores settings as JSON under %LOCALAPPDATA%\WebGuardInspector\settings.json.</summary>
public sealed class JsonSettingsStore(string filePath) : ISettingsStore
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WebGuardInspector", "settings.json");

    public string FilePath { get; } = filePath;

    public AppSettings Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return new AppSettings();
            return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath), Options) ?? new AppSettings();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return new AppSettings();
        }
    }

    public void Save(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var directory = Path.GetDirectoryName(FilePath);
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
        var temp = FilePath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(settings, Options));
        File.Move(temp, FilePath, overwrite: true);
    }
}

/// <summary>Single source of truth for settings shared by all view models.</summary>
public sealed class SettingsService(ISettingsStore store)
{
    private AppSettings _current = store.Load();

    public event EventHandler? Changed;

    public AppSettings Current => _current;

    public void Update(Func<AppSettings, AppSettings> change)
    {
        ArgumentNullException.ThrowIfNull(change);
        _current = change(_current);
        store.Save(_current);
        Changed?.Invoke(this, EventArgs.Empty);
    }
}
