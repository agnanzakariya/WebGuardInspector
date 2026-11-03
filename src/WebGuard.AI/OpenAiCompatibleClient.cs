using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WebGuard.AI;

public sealed record ChatMessage(
    [property: JsonPropertyName("role")] string Role,
    [property: JsonPropertyName("content")] string Content);

/// <summary>
/// Minimal client for the OpenAI-compatible API served by LM Studio, Ollama (/v1) and llama.cpp.
/// No API key is sent; the endpoint is a local server.
/// </summary>
public sealed class OpenAiCompatibleClient(HttpClient http)
{
    /// <summary>Model ids served by the endpoint (GET /models).</summary>
    public async Task<IReadOnlyList<string>> ListModelsAsync(Uri endpoint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        using var response = await http.GetAsync(Combine(endpoint, "models"), cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
        return document.RootElement.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array
            ? data.EnumerateArray()
                .Select(m => m.TryGetProperty("id", out var id) ? id.GetString() : null)
                .OfType<string>()
                .ToArray()
            : [];
    }

    /// <summary>Single non-streaming chat completion; returns the assistant message text.</summary>
    /// <remarks>
    /// Asks for <c>reasoning_effort: "none"</c>: reasoning models (Qwen3.x, gpt-oss) otherwise spend the whole token budget
    /// "thinking" on CPU and return no answer. LM Studio honours it; servers that reject the field are retried without it.
    /// </remarks>
    public async Task<string> CompleteAsync(Uri endpoint, string model, IReadOnlyList<ChatMessage> messages, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        var request = new ChatRequest(model, messages, Temperature: 0.2, MaxTokens: 1200, Stream: false, ReasoningEffort: "none");
        var (status, body) = await PostAsync(endpoint, request, cancellationToken).ConfigureAwait(false);
        if (status == 400 && body.Contains("reasoning", StringComparison.OrdinalIgnoreCase))
            (status, body) = await PostAsync(endpoint, request with { ReasoningEffort = null }, cancellationToken).ConfigureAwait(false);
        if (status is < 200 or > 299)
            throw new HttpRequestException($"AI server returned {status}: {Truncate(body, 300)}");

        using var document = JsonDocument.Parse(body);
        var message = document.RootElement.TryGetProperty("choices", out var choices) && choices.ValueKind == JsonValueKind.Array &&
                      choices.GetArrayLength() > 0 && choices[0].TryGetProperty("message", out var m)
            ? m
            : default;
        var content = message.ValueKind == JsonValueKind.Object && message.TryGetProperty("content", out var text) && text.ValueKind == JsonValueKind.String
            ? text.GetString()
            : null;
        if (string.IsNullOrWhiteSpace(content))
        {
            var reasoned = message.ValueKind == JsonValueKind.Object && message.TryGetProperty("reasoning_content", out var r) &&
                           r.ValueKind == JsonValueKind.String && r.GetString()!.Length > 0;
            throw new HttpRequestException(reasoned
                ? "The model used its whole token budget on reasoning and gave no answer. Turn off thinking for this model in LM Studio, or load a non-reasoning model."
                : "AI server response had no message content.");
        }
        return content;
    }

    private async Task<(int Status, string Body)> PostAsync(Uri endpoint, ChatRequest request, CancellationToken cancellationToken)
    {
        using var response = await http.PostAsJsonAsync(Combine(endpoint, "chat/completions"), request, cancellationToken).ConfigureAwait(false);
        return ((int)response.StatusCode, await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
    }

    /// <summary>Embedding models are listed by the same endpoint but cannot chat.</summary>
    public static bool IsChatModel(string id) =>
        !id.Contains("embed", StringComparison.OrdinalIgnoreCase) && !id.Contains("rerank", StringComparison.OrdinalIgnoreCase);

    private static Uri Combine(Uri endpoint, string path) => new(endpoint.AbsoluteUri.TrimEnd('/') + "/" + path);

    private static string Truncate(string text, int max) => text.Length <= max ? text : text[..max] + "…";

    private sealed record ChatRequest(
        [property: JsonPropertyName("model")] string Model,
        [property: JsonPropertyName("messages")] IReadOnlyList<ChatMessage> Messages,
        [property: JsonPropertyName("temperature")] double Temperature,
        [property: JsonPropertyName("max_tokens")] int MaxTokens,
        [property: JsonPropertyName("stream")] bool Stream,
        [property: JsonPropertyName("reasoning_effort"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ReasoningEffort);
}
