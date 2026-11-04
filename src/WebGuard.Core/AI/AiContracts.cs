using System.Text.Json.Serialization;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;

namespace WebGuard.Core.AI;

/// <summary>Context handed to the AI analyst. Built by MCP tools with folder scope and secret redaction applied.</summary>
/// <param name="PriorKnowledge">Earlier human verdicts on similar findings from the Second Brain (prompt text), if any.</param>
public sealed record FindingContext(SecurityFinding Finding, string RedactedSourceExcerpt, IReadOnlyList<SecurityFinding> SimilarFindings,
    string? PriorKnowledge = null);

/// <summary>AI output is always a hypothesis until a human validates it.</summary>
public sealed record AiAnalysis(
    Guid FindingId,
    string Model,
    string Summary,
    string WhyRisky,
    string? ProposedRemediation,
    Confidence Confidence,
    bool IsVerified,
    DateTimeOffset CreatedAtUtc);

public interface IAiSecurityAnalyst
{
    string DisplayName { get; }
    Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken);
    Task<AiAnalysis> AnalyzeAsync(FindingContext context, CancellationToken cancellationToken);
}

[JsonConverter(typeof(JsonStringEnumConverter<McpToolAccess>))]
public enum McpToolAccess { ReadOnly, ExecutesAllowListedTool, NetworkLookup, WritesKnowledge }

public sealed record McpToolDescriptor(string Name, string Description, McpToolAccess Access, bool RequiresHumanApproval);

/// <summary>The MCP tool surface defined in the project instructions. Least privilege: read-only by default.</summary>
public static class McpToolCatalog
{
    public static IReadOnlyList<McpToolDescriptor> Tools { get; } =
    [
        new("list_project_files", "List files inside the user-approved scan root.", McpToolAccess.ReadOnly, false),
        new("read_source_context", "Return a redacted snippet around a source location.", McpToolAccess.ReadOnly, false),
        new("get_dependency_manifest", "Read package manifests and lockfiles.", McpToolAccess.ReadOnly, false),
        new("run_security_rules", "Run an allow-listed security engine on the scan root.", McpToolAccess.ExecutesAllowListedTool, true),
        new("lookup_vulnerability", "Query CVE/GHSA/OSV advisories for a package.", McpToolAccess.NetworkLookup, true),
        new("lookup_malware_hash", "Check a SHA-256 against malware intelligence.", McpToolAccess.NetworkLookup, true),
        new("search_similar_findings", "Semantic search over the Second Brain.", McpToolAccess.ReadOnly, false),
        new("propose_remediation", "Draft a fix; never applies it to files.", McpToolAccess.ReadOnly, false),
        new("save_security_finding", "Persist a validated, deduplicated finding.", McpToolAccess.WritesKnowledge, true),
    ];

    /// <summary>Tools that read or write the Second Brain vault; they report an error until a vault is configured.</summary>
    public static IReadOnlySet<string> SecondBrainTools { get; } = new HashSet<string>(StringComparer.Ordinal) { "search_similar_findings", "save_security_finding" };

    /// <summary>Approval-gated tools a person can pre-approve when registering the server with a client.</summary>
    public static IReadOnlyList<string> ApprovableTools { get; } = Tools.Where(t => t.RequiresHumanApproval).Select(t => t.Name).ToArray();
}

/// <summary>How an MCP client launches the server for one project folder.</summary>
/// <param name="ConfigJson">"mcpServers" JSON block for clients such as LM Studio, Claude Desktop or Cursor.</param>
/// <param name="ClaudeCodeCommand">Equivalent <c>claude mcp add</c> command line.</param>
public sealed record McpClientSetup(string ExecutablePath, IReadOnlyList<string> Arguments, string ConfigJson, string ClaudeCodeCommand);

/// <summary>
/// Hosts the local MCP server (stdio) that exposes <see cref="McpToolCatalog"/> to MCP clients. With stdio the client
/// starts the server process, so the host's job is to validate the folder and describe how to launch it.
/// </summary>
public interface IMcpServerHost
{
    IReadOnlyList<McpToolDescriptor> Tools { get; }
    Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken);
    Task StartAsync(string allowedRoot, CancellationToken cancellationToken);
    Task StopAsync(CancellationToken cancellationToken);
    McpClientSetup GetClientSetup(string allowedRoot, IReadOnlyCollection<string> approvedTools);
}
