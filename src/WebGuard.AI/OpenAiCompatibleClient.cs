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
    public async Task<string> CompleteAsync(Uri endpoint, string model, IReadOnlyList<ChatMessage> messages, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        var request = new ChatRequest(model, messages, Temperature: 0.2, MaxTokens: 1200, Stream: false);
        using var response = await http.PostAsJsonAsync(Combine(endpoint, "chat/completions"), request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException($"AI server returned {(int)response.StatusCode}: {Truncate(body, 300)}");

        using var document = JsonDocument.Parse(body);
        var content = document.RootElement.TryGetProperty("choices", out var choices) && choices.ValueKind == JsonValueKind.Array &&
                      choices.GetArrayLength() > 0 && choices[0].TryGetProperty("message", out var message) &&
                      message.TryGetProperty("content", out var text) && text.ValueKind == JsonValueKind.String
            ? text.GetString()
            : null;
        return content ?? throw new HttpRequestException("AI server response had no message content.");
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
        [property: JsonPropertyName("stream")] bool Stream);
}
