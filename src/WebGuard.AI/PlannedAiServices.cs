using WebGuard.Core.AI;
using WebGuard.Core.Detection;

namespace WebGuard.AI;

/// <summary>Placeholder analyst for tests and for hosts without a local model configured. Performs no calls.</summary>
public sealed class PlannedAiSecurityAnalyst : IAiSecurityAnalyst
{
    public string DisplayName => "AI Security Analyst (not configured)";

    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new EngineStatus(EngineAvailability.Disabled, null, null, "No AI analyst configured."));

    public Task<AiAnalysis> AnalyzeAsync(FindingContext context, CancellationToken cancellationToken) =>
        throw new InvalidOperationException("No AI analyst configured.");
}

/// <summary>Placeholder MCP host exposing the tool catalog without a server executable.</summary>
public sealed class PlannedMcpServerHost : IMcpServerHost
{
    public IReadOnlyList<McpToolDescriptor> Tools => McpToolCatalog.Tools;

    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new EngineStatus(EngineAvailability.NotInstalled, null, null, "MCP server executable not configured."));

    public Task StartAsync(string allowedRoot, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public McpClientSetup GetClientSetup(string allowedRoot, IReadOnlyCollection<string> approvedTools) =>
        new(string.Empty, [], "{}", string.Empty);
}
