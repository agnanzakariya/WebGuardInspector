using System.Net;
using System.Text;
using WebGuard.Core.Detection;
using WebGuard.Detection;

namespace WebGuard.Tests;

/// <summary>Records requests and answers them from a handler; never starts a process.</summary>
internal sealed class FakeProcessRunner(Func<ProcessRunRequest, ProcessRunResult> handler) : IExternalProcessRunner
{
    public List<ProcessRunRequest> Requests { get; } = [];

    public Task<ProcessRunResult> RunAsync(ProcessRunRequest request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        return Task.FromResult(handler(request));
    }

    public static ProcessRunResult Ok(string stdout, int exitCode = 0) =>
        new(exitCode, stdout, string.Empty, TimeSpan.FromMilliseconds(5), false, false);

    public static bool IsVersionProbe(ProcessRunRequest r) =>
        r.Arguments is ["--version"] or ["version"];
}

internal sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;
    public override DateTimeOffset GetUtcNow() => Now;
}

/// <summary>Serves canned HTTP responses and records what was sent.</summary>
internal sealed class FakeHttpHandler(Func<HttpRequestMessage, string> respond) : HttpMessageHandler
{
    public List<(Uri Uri, string Body, string? AuthKey)> Requests { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        Requests.Add((request.RequestUri!, body, request.Headers.TryGetValues("Auth-Key", out var v) ? v.Single() : null));
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(respond(request), Encoding.UTF8, "application/json") };
    }
}

internal static class TestEngines
{
    /// <summary>The default catalog with every engine disabled, so tests never depend on tools installed on the machine.</summary>
    public static IReadOnlyList<ISecurityEngine> Offline() => SecurityEngineCatalog.CreateDefault(
        new FakeProcessRunner(_ => throw new InvalidOperationException("No process may start in this test.")),
        id => new ExternalToolOptions(id, null, false, [], "Disabled for tests."));
}
