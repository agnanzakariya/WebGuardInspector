using WebGuard.Core.AI;
using WebGuard.Core.Detection;

namespace WebGuard.AI;

/// <summary>Local AI analyst (Ollama via MCP) — Phase 3 placeholder.</summary>
public sealed class PlannedAiSecurityAnalyst : IAiSecurityAnalyst
{
    public string DisplayName => "AI Security Analyst (Ollama, local)";

    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
        Task.FromResult(EngineStatus.Planned("Phase 3"));

    public Task<AiAnalysis> AnalyzeAsync(FindingContext context, CancellationToken cancellationToken) =>
        throw new NotSupportedException("AI analysis is scheduled for Phase 3.");
}

/// <summary>Local MCP server — Phase 3 placeholder exposing the planned tool catalog.</summary>
public sealed class PlannedMcpServerHost : IMcpServerHost
{
    public IReadOnlyList<McpToolDescriptor> Tools => McpToolCatalog.Tools;

    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
        Task.FromResult(EngineStatus.Planned("Phase 3"));

    public Task StartAsync(string allowedRoot, CancellationToken cancellationToken) =>
        throw new NotSupportedException("MCP server is scheduled for Phase 3.");

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
