namespace WebGuard.Core.AI;

/// <summary>How the local AI server should be started.</summary>
/// <param name="Model">Model key to load; empty loads the first downloaded chat model.</param>
/// <param name="GpuOffload">"auto" (let the server decide), "off", "max", or a share such as "0.75".</param>
/// <param name="ContextLength">Context window in tokens.</param>
public sealed record LocalAiStartup(string? Model, string GpuOffload, int ContextLength)
{
    public const string AutoGpu = "auto";
    public const int DefaultContextLength = 8192;

    /// <summary>"auto", "off", "max" or a number from 0 to 1.</summary>
    public static bool IsValidGpuOffload(string? value) =>
        value?.Trim().ToLowerInvariant() is AutoGpu or "off" or "max" ||
        double.TryParse(value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var share) && share is >= 0 and <= 1;
}

/// <summary>Outcome of starting the local AI: ready (and with which model) or why not.</summary>
public sealed record LocalAiStartResult(bool Ready, string Message, string? Model = null);

/// <summary>Starts a local AI server (e.g. LM Studio) and loads a chat model, so the AI Analyst and local fixing are ready.</summary>
public interface ILocalAiLauncher
{
    /// <summary>The server's command-line tool is installed.</summary>
    bool IsAvailable { get; }

    Task<LocalAiStartResult> EnsureRunningAsync(LocalAiStartup options, IProgress<string>? progress, CancellationToken cancellationToken);
}
