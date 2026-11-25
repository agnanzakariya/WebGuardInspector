using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using WebGuard.Core.AI;
using WebGuard.Core.Detection;

namespace WebGuard.AI;

/// <summary>
/// Starts LM Studio's local server and loads a chat model with its command-line tool <c>lms</c>
/// (%USERPROFILE%\.lmstudio\bin\lms.exe): <c>lms server start</c>, then <c>lms load</c> when no chat model is loaded yet.
/// The server listens on localhost only; nothing is downloaded.
/// </summary>
public sealed partial class LmStudioLauncher(IExternalProcessRunner runner, Func<string?>? locateLms = null) : ILocalAiLauncher
{
    private static readonly TimeSpan QuickTimeout = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan LoadTimeout = TimeSpan.FromMinutes(15);

    private readonly Func<string?> _locate = locateLms ?? DefaultLmsPath;

    /// <summary>Where LM Studio installs its CLI, or null when it is not there.</summary>
    public static string? DefaultLmsPath()
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".lmstudio", "bin", "lms.exe");
        return File.Exists(path) ? path : null;
    }

    public bool IsAvailable => _locate() is not null;

    public async Task<LocalAiStartResult> EnsureRunningAsync(LocalAiStartup options, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (_locate() is not { } lms)
            return new LocalAiStartResult(false, "LM Studio's command-line tool (lms) was not found. Install LM Studio and open it once.");

        progress?.Report("Starting the LM Studio server…");
        var server = await RunAsync(lms, ["server", "start"], QuickTimeout, cancellationToken).ConfigureAwait(false);
        if (server.ExitCode != 0 || server.TimedOut)
            return new LocalAiStartResult(false, "LM Studio server did not start: " + Tail(server));

        var loaded = await LoadedModelsAsync(lms, cancellationToken).ConfigureAwait(false);
        var wanted = string.IsNullOrWhiteSpace(options.Model) ? null : options.Model.Trim();
        var already = loaded.FirstOrDefault(m => wanted is null || m.Equals(wanted, StringComparison.OrdinalIgnoreCase));
        if (already is not null) return new LocalAiStartResult(true, $"Local AI ready: {already} is loaded.", already);

        var model = wanted ?? await FirstChatModelAsync(lms, cancellationToken).ConfigureAwait(false);
        if (model is null)
            return new LocalAiStartResult(false, "No chat model is downloaded in LM Studio. Download one in LM Studio first.");

        progress?.Report($"Loading {model} in LM Studio… this can take a few minutes.");
        List<string> args = ["load", model, "-c", Math.Max(512, options.ContextLength).ToString(CultureInfo.InvariantCulture), "-y"];
        var gpu = options.GpuOffload.Trim().ToLowerInvariant();
        if (gpu != LocalAiStartup.AutoGpu && LocalAiStartup.IsValidGpuOffload(gpu)) args.AddRange(["--gpu", gpu]);
        var load = await RunAsync(lms, args, LoadTimeout, cancellationToken).ConfigureAwait(false);
        if (load.TimedOut) return new LocalAiStartResult(false, $"Loading {model} took longer than {LoadTimeout.TotalMinutes:0} minutes.");
        if (load.ExitCode != 0) return new LocalAiStartResult(false, $"LM Studio could not load {model}: " + Tail(load));

        return new LocalAiStartResult(true, $"Local AI ready: {model} loaded" +
                                            (gpu == LocalAiStartup.AutoGpu ? "." : $" (GPU offload {gpu}).") , model);
    }

    /// <summary>Identifiers of the loaded chat models (embedding models are ignored).</summary>
    private async Task<List<string>> LoadedModelsAsync(string lms, CancellationToken cancellationToken)
    {
        var ps = await RunAsync(lms, ["ps", "--json"], QuickTimeout, cancellationToken).ConfigureAwait(false);
        return Models(ps.StandardOutput, loaded: true);
    }

    private async Task<string?> FirstChatModelAsync(string lms, CancellationToken cancellationToken)
    {
        var ls = await RunAsync(lms, ["ls", "--json"], QuickTimeout, cancellationToken).ConfigureAwait(false);
        return Models(ls.StandardOutput, loaded: false).FirstOrDefault();
    }

    /// <summary>Chat-model keys from <c>lms ps --json</c> or <c>lms ls --json</c>; the JSON array may follow status lines.</summary>
    public static List<string> Models(string output, bool loaded)
    {
        var start = (output ?? string.Empty).IndexOf('[', StringComparison.Ordinal);
        if (start < 0) return [];
        try
        {
            using var doc = JsonDocument.Parse(output![start..]);
            var keys = new List<string>();
            foreach (var item in doc.RootElement.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object) continue;
                if (item.TryGetProperty("type", out var type) && type.GetString() is { } t && !t.Equals("llm", StringComparison.OrdinalIgnoreCase)) continue;
                var name = new[] { loaded ? "identifier" : "modelKey", "modelKey", "identifier", "path" }
                    .Select(p => item.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null)
                    .FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
                if (name is not null) keys.Add(name);
            }
            return keys;
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private Task<ProcessRunResult> RunAsync(string lms, IReadOnlyList<string> args, TimeSpan timeout, CancellationToken cancellationToken) =>
        runner.RunAsync(new ProcessRunRequest(lms, args, Path.GetTempPath(), timeout, 1024 * 1024), cancellationToken);

    /// <summary>Last meaningful line of the tool's output, without colour codes and progress spinners.</summary>
    private static string Tail(ProcessRunResult result)
    {
        var text = AnsiCodes().Replace(result.StandardError + "\n" + result.StandardOutput, string.Empty);
        var line = text.Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .LastOrDefault(l => !l.StartsWith("Loading ", StringComparison.Ordinal) && l.Any(char.IsLetter));
        return line ?? $"exit code {result.ExitCode}";
    }

    [GeneratedRegex(@"\x1B\[[0-9;?]*[A-Za-z]")]
    private static partial Regex AnsiCodes();
}
