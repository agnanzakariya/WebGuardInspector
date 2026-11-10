using System.Net;

namespace WebGuard.Intelligence;

/// <summary>
/// Retries an HTTP request when the service had a temporary problem: 408, 429, 500, 502, 503, 504, a dropped connection
/// or a client time-out. Waits between attempts (or what the service asks for in Retry-After, at most 10 s) and returns
/// the last response, so callers still see a lasting error. Cancellation by the caller is never retried.
/// </summary>
public sealed class TransientRetry(IReadOnlyList<TimeSpan>? delays = null)
{
    private static readonly TimeSpan MaxRetryAfter = TimeSpan.FromSeconds(10);

    /// <summary>Two retries after 1 s and 3 s.</summary>
    public static TransientRetry Default { get; } = new();

    /// <summary>No waiting between attempts (tests).</summary>
    public static TransientRetry Immediate { get; } = new([TimeSpan.Zero, TimeSpan.Zero]);

    public IReadOnlyList<TimeSpan> Delays { get; } = delays ?? [TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(3)];

    /// <param name="createRequest">Builds a fresh request for every attempt (a request cannot be sent twice).</param>
    public async Task<HttpResponseMessage> SendAsync(HttpClient http, Func<HttpRequestMessage> createRequest, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(createRequest);
        for (var attempt = 0; ; attempt++)
        {
            var last = attempt >= Delays.Count;
            HttpResponseMessage response;
            using (var request = createRequest())
            {
                try
                {
                    response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
                }
                catch (HttpRequestException) when (!last)
                {
                    await Task.Delay(Delays[attempt], cancellationToken).ConfigureAwait(false);
                    continue;
                }
                catch (TaskCanceledException) when (!last && !cancellationToken.IsCancellationRequested)
                {
                    // HttpClient.Timeout elapsed.
                    await Task.Delay(Delays[attempt], cancellationToken).ConfigureAwait(false);
                    continue;
                }
            }

            if (last || !IsTransient(response.StatusCode)) return response;
            var wait = response.Headers.RetryAfter?.Delta is { } delta && delta > TimeSpan.Zero
                ? (delta < MaxRetryAfter ? delta : MaxRetryAfter)
                : Delays[attempt];
            response.Dispose();
            await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
        }
    }

    public static bool IsTransient(HttpStatusCode code) => code is HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests
        or HttpStatusCode.InternalServerError or HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout;
}
