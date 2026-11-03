namespace WebGuard.AI;

/// <summary>Local AI runtime settings, read on every call so Settings changes apply without a restart.</summary>
/// <param name="Enabled">Master switch for AI analysis.</param>
/// <param name="Endpoint">OpenAI-compatible base URL, e.g. http://127.0.0.1:1234/v1 (LM Studio) or http://127.0.0.1:11434/v1 (Ollama).</param>
/// <param name="Model">Model id; empty selects the first loaded chat model.</param>
public sealed record AiSettings(bool Enabled, string Endpoint, string? Model)
{
    public const string LmStudioEndpoint = "http://127.0.0.1:1234/v1";
    public const string OllamaEndpoint = "http://127.0.0.1:11434/v1";

    public static AiSettings Default { get; } = new(true, LmStudioEndpoint, null);

    /// <summary>Only loopback endpoints are accepted, so source excerpts never leave the machine.</summary>
    public bool TryGetLocalEndpoint(out Uri endpoint, out string error)
    {
        endpoint = null!;
        error = string.Empty;
        if (!Uri.TryCreate(Endpoint?.Trim().TrimEnd('/'), UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
        {
            error = "AI endpoint must be an http(s) URL such as " + LmStudioEndpoint + ".";
            return false;
        }
        if (!uri.IsLoopback)
        {
            error = "Only local AI endpoints (localhost / 127.0.0.1) are allowed; source excerpts never leave this machine.";
            return false;
        }
        endpoint = uri;
        return true;
    }
}
