using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using WebGuard.Core.Detection;
using WebGuard.Core.Fixing;

namespace WebGuard.AI;

/// <summary>
/// Proposes fixes with a model on this PC (LM Studio, Ollama: OpenAI-compatible API on a loopback endpoint), using the
/// same prompt and answer format as <see cref="ClaudeCodeFixer"/>. Nothing leaves the machine. Small models have small
/// context windows, so requests use <see cref="FixLimits.LocalModel"/> (excerpts sooner) and answers are less reliable:
/// every edit is still checked against the file and reviewed as a diff before it is applied.
/// </summary>
public sealed partial class LocalModelCodeFixer(OpenAiCompatibleClient client, Func<AiSettings> settings, Func<bool> enabled,
    TimeProvider? timeProvider = null) : ICodeFixer
{
    private static readonly TimeSpan StatusTimeout = TimeSpan.FromSeconds(4);
    /// <summary>A full fix answer (up to 2,500 tokens) from a large model on CPU can take most of an hour.</summary>
    public static readonly TimeSpan FixTimeout = TimeSpan.FromMinutes(60);
    private const int MaxAnswerTokens = 2500;   // with the prompt and file this stays inside an 8k context
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    /// <summary>Claude's rules plus an explicit reply format, since local servers do not enforce a JSON schema.</summary>
    public const string SystemPrompt = ClaudeCodeFixer.SystemPrompt + "\n" +
        "Reply with ONLY one JSON object and nothing before or after it:\n" +
        "{\"verdict\": \"fix|false_positive|cannot_fix\", \"explanation\": \"...\", \"confidence\": \"low|medium|high\", " +
        "\"edits\": [{\"old_text\": \"exact text from the file\", \"new_text\": \"replacement\"}], \"follow_up_command\": \"\"}";

    public string DisplayName => "Local model (LM Studio / Ollama)";
    public string ShortName => "the local model";
    public FixLimits Limits => FixLimits.LocalModel;

    public async Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        if (!enabled()) return new EngineStatus(EngineAvailability.Disabled, null, null, "AI fixing is turned off in Settings.");
        var s = settings();
        if (!s.TryGetLocalEndpoint(out var endpoint, out var error)) return new EngineStatus(EngineAvailability.Error, null, null, error);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(StatusTimeout);
        try
        {
            var (model, problem) = await ResolveModelAsync(endpoint, s, timeout.Token).ConfigureAwait(false);
            return model is null
                ? new EngineStatus(EngineAvailability.NotInstalled, null, endpoint.AbsoluteUri, problem)
                : new EngineStatus(EngineAvailability.Ready, null, endpoint.AbsoluteUri, $"Model {model} at {endpoint.Authority}. Runs on this PC.");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException && !cancellationToken.IsCancellationRequested)
        {
            return new EngineStatus(EngineAvailability.NotInstalled, null, endpoint.AbsoluteUri,
                $"No AI server at {endpoint.Authority}. Start the LM Studio local server (or Ollama) and load a chat model.");
        }
    }

    public async Task<FixProposal> ProposeAsync(FixRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!enabled()) throw new InvalidOperationException("AI fixing is turned off in Settings.");
        var s = settings();
        if (!s.TryGetLocalEndpoint(out var endpoint, out var error)) throw new InvalidOperationException(error);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(FixTimeout);
        string reply;
        string model;
        try
        {
            var (resolved, problem) = await ResolveModelAsync(endpoint, s, timeout.Token).ConfigureAwait(false);
            model = resolved ?? throw new InvalidOperationException(problem);
            reply = await client.CompleteAsync(endpoint, model,
                [new ChatMessage("system", SystemPrompt), new ChatMessage("user", ClaudeCodeFixer.BuildPrompt(request))],
                timeout.Token, MaxAnswerTokens).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new InvalidOperationException("Local model: " + ex.Message, ex);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new InvalidOperationException($"The local model did not answer within {FixTimeout.TotalMinutes:0} minutes. " +
                                                "Use a smaller or faster model, or close other programs to free memory.");
        }
        return ParseReply(request.Finding.Id, model, reply, _time.GetUtcNow());
    }

    /// <summary>The JSON object in the reply, also inside a ```json fence or after a &lt;think&gt; block.</summary>
    public static FixProposal ParseReply(Guid findingId, string model, string reply, DateTimeOffset createdAtUtc)
    {
        var text = ThinkBlock().Replace(reply ?? string.Empty, string.Empty).Trim();
        var start = text.IndexOf('{', StringComparison.Ordinal);
        var end = text.LastIndexOf('}');
        if (start >= 0 && end > start)
        {
            try
            {
                using var document = JsonDocument.Parse(text[start..(end + 1)]);
                return ClaudeCodeFixer.FromAnswer(findingId, model, document.RootElement, createdAtUtc);
            }
            catch (JsonException)
            {
                // Reported below.
            }
        }
        throw new InvalidOperationException("The local model did not answer in the expected JSON format. Try again, or use a larger model: " +
                                            (text.Length > 300 ? text[..300] + "…" : text));
    }

    private async Task<(string? Model, string Problem)> ResolveModelAsync(Uri endpoint, AiSettings s, CancellationToken cancellationToken)
    {
        var models = await client.ListModelsAsync(endpoint, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(s.Model))
        {
            var wanted = s.Model.Trim();
            return models.Contains(wanted, StringComparer.OrdinalIgnoreCase)
                ? (wanted, string.Empty)
                : (null, $"Model '{wanted}' is not available at {endpoint.Authority}. Available: {(models.Count == 0 ? "none" : string.Join(", ", models))}.");
        }
        var chat = models.FirstOrDefault(OpenAiCompatibleClient.IsChatModel);
        return chat is null
            ? (null, $"No chat model is loaded at {endpoint.Authority}. Load one in LM Studio.")
            : (chat, string.Empty);
    }

    [GeneratedRegex(@"<think>[\s\S]*?</think>", RegexOptions.IgnoreCase)]
    private static partial Regex ThinkBlock();
}

/// <summary>Uses Claude or the local model for fixing, as chosen in Settings (read on every call).</summary>
public sealed class SelectableCodeFixer(Func<bool> useLocalModel, ICodeFixer claude, ICodeFixer localModel) : ICodeFixer
{
    private ICodeFixer Current => useLocalModel() ? localModel : claude;

    public string DisplayName => Current.DisplayName;
    public string ShortName => Current.ShortName;
    public FixLimits Limits => Current.Limits;
    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) => Current.GetStatusAsync(cancellationToken);
    public Task<FixProposal> ProposeAsync(FixRequest request, CancellationToken cancellationToken) => Current.ProposeAsync(request, cancellationToken);
}
