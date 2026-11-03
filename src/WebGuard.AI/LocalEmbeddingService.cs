using WebGuard.Core.Knowledge;

namespace WebGuard.AI;

/// <summary>
/// Embeddings from the local AI server (LM Studio, Ollama) using its embedding model, e.g. nomic-embed-text.
/// Same loopback-only rule as the analyst: note text never leaves the machine.
/// </summary>
public sealed class LocalEmbeddingService(OpenAiCompatibleClient client, Func<AiSettings> settings) : ITextEmbeddingService
{
    private string? _model;

    public string ModelId => _model ?? "embedding";

    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken)
    {
        var s = settings();
        if (!s.Enabled || !s.TryGetLocalEndpoint(out var endpoint, out _)) return false;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(4));
        try
        {
            _model = (await client.ListModelsAsync(endpoint, timeout.Token).ConfigureAwait(false))
                .FirstOrDefault(id => id.Contains("embed", StringComparison.OrdinalIgnoreCase));
            return _model is not null;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return false;
        }
    }

    public async Task<IReadOnlyList<float[]>> EmbedAsync(IReadOnlyList<string> texts, bool isQuery, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(texts);
        var s = settings();
        if (!s.TryGetLocalEndpoint(out var endpoint, out var error)) throw new InvalidOperationException(error);
        if (_model is null && !await IsAvailableAsync(cancellationToken).ConfigureAwait(false))
            throw new InvalidOperationException("No embedding model is available on the local AI server.");
        // nomic-embed expects task prefixes; other models ignore them harmlessly only if we leave them off.
        var inputs = _model!.Contains("nomic", StringComparison.OrdinalIgnoreCase)
            ? texts.Select(t => (isQuery ? "search_query: " : "search_document: ") + t).ToArray()
            : texts;
        return await client.EmbedAsync(endpoint, _model, inputs, cancellationToken).ConfigureAwait(false);
    }
}
