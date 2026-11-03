using System.Text.Json;
using System.Text.Json.Nodes;
using WebGuard.Core.AI;
using WebGuard.Core.Detection;
using WebGuard.Core.Scanning;

namespace WebGuard.AI;

/// <summary>
/// Describes the bundled WebGuard.Mcp.exe stdio server. MCP clients launch it themselves with
/// <c>--root &lt;folder&gt;</c> and optional <c>--allow</c> pre-approvals, so this host validates and prints that command.
/// </summary>
public sealed class StdioMcpServerHost(string executablePath) : IMcpServerHost
{
    public const string ServerName = "webguard";

    public static string BundledExecutablePath => Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? "WebGuard.Mcp.exe" : "WebGuard.Mcp");

    public IReadOnlyList<McpToolDescriptor> Tools => McpToolCatalog.Tools;

    public string? AllowedRoot { get; private set; }

    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) => Task.FromResult(File.Exists(executablePath)
        ? new EngineStatus(EngineAvailability.Ready, null, executablePath,
            "Stdio server; MCP clients start it per project folder. Read-only tools are always on; others need --allow.")
        : new EngineStatus(EngineAvailability.NotInstalled, null, null, "WebGuard.Mcp.exe was not found next to the application."));

    public Task StartAsync(string allowedRoot, CancellationToken cancellationToken)
    {
        AllowedRoot = new ProjectScope(allowedRoot).Root;
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        AllowedRoot = null;
        return Task.CompletedTask;
    }

    public McpClientSetup GetClientSetup(string allowedRoot, IReadOnlyCollection<string> approvedTools)
    {
        ArgumentNullException.ThrowIfNull(approvedTools);
        var root = Path.GetFullPath(allowedRoot);
        var approved = approvedTools.Where(t => McpToolCatalog.ApprovableTools.Contains(t, StringComparer.Ordinal)).ToArray();
        List<string> args = ["--root", root];
        if (approved.Length > 0) args.AddRange(["--allow", string.Join(',', approved)]);

        var config = new JsonObject
        {
            ["mcpServers"] = new JsonObject
            {
                [ServerName] = new JsonObject
                {
                    ["command"] = executablePath,
                    ["args"] = new JsonArray([.. args.Select(a => (JsonNode)a)]),
                },
            },
        };
        var claude = "claude mcp add " + ServerName + " -- " + string.Join(' ', new[] { executablePath }.Concat(args).Select(Quote));
        return new McpClientSetup(executablePath, args, config.ToJsonString(new JsonSerializerOptions { WriteIndented = true }), claude);
    }

    private static string Quote(string value) => value.Contains(' ', StringComparison.Ordinal) || value.Length == 0 ? "\"" + value + "\"" : value;
}
