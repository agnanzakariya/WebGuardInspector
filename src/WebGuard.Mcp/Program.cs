using System.Text;
using WebGuard.AI;
using WebGuard.Core;
using WebGuard.Core.Scanning;
using WebGuard.Detection;
using WebGuard.Intelligence;
using WebGuard.Mcp;
using WebGuard.Presentation.Services;
using WebGuard.Scanner;

// webguard-mcp --root <project folder> [--allow run_security_rules,lookup_vulnerability,lookup_malware_hash|all] [--audit-log <file>]
// Started by an MCP client over stdio. stdout carries protocol messages only; diagnostics go to stderr.
var stdout = Console.OpenStandardOutput();
Console.SetOut(Console.Error);

string? root = null;
string? auditPath = null;
var allowed = new List<string>();
for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--root" when i + 1 < args.Length: root = args[++i]; break;
        case "--allow" when i + 1 < args.Length: allowed.AddRange(args[++i].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)); break;
        case "--audit-log" when i + 1 < args.Length: auditPath = args[++i]; break;
        case "--version": Console.Error.WriteLine($"{AppInfo.Name} MCP server {AppInfo.Version}"); return 0;
        default:
            Console.Error.WriteLine($"webguard-mcp: unknown argument '{args[i]}'.");
            Console.Error.WriteLine("Usage: WebGuard.Mcp --root <project folder> [--allow tool1,tool2|all] [--audit-log <file>]");
            return 2;
    }
}
if (root is null)
{
    Console.Error.WriteLine("webguard-mcp: --root <project folder> is required; the server only works inside that folder.");
    return 2;
}

ProjectScope scope;
try
{
    scope = new ProjectScope(root);
}
catch (DirectoryNotFoundException ex)
{
    Console.Error.WriteLine("webguard-mcp: " + ex.Message);
    return 2;
}

// Same settings, consent and engines as the desktop app.
var store = new JsonSettingsStore(JsonSettingsStore.DefaultPath);
AppSettings Settings() => store.Load();
IntelligenceSettings Intelligence() { var s = Settings(); return new(s.AllowExternalIntelligence, s.AbuseChAuthKey); }
AiSettings Ai() { var s = Settings(); return new(s.AiEnabled, s.AiEndpoint, s.AiModel); }

using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
http.DefaultRequestHeaders.UserAgent.ParseAdd($"WebGuardInspector/{AppInfo.Version}");
using var aiHttp = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
var cache = new FileIntelligenceCache(FileIntelligenceCache.DefaultDirectory);
var kev = new CisaKevCatalog(http, cache);
var runner = new ExternalProcessRunner();
var services = new McpServices(
    Settings,
    () => SecurityEngineCatalog.CreateDefault(runner, id => Settings().ToolOptions(id)),
    [new KnownExploitedEnricher(kev, Intelligence)],
    new OsvVulnerabilityIntelligence(http, cache, Intelligence, kev: kev),
    [new MalwareBazaarHashIntelligence(http, cache, Intelligence), new ThreatFoxHashIntelligence(http, cache, Intelligence)],
    new LocalAiSecurityAnalyst(new OpenAiCompatibleClient(aiHttp), Ai));

var toolset = new McpToolset(scope, services, new McpAuditLog(auditPath ?? McpAuditLog.DefaultPath), allowed);
Console.Error.WriteLine($"webguard-mcp {AppInfo.Version}: root={scope.Root}; tools={string.Join(",", toolset.Enabled)}");

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
using var input = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false));
await using var output = new StreamWriter(stdout, new UTF8Encoding(false)) { NewLine = "\n", AutoFlush = true };
try
{
    await new McpServer(toolset).RunAsync(input, output, cts.Token);
}
catch (OperationCanceledException)
{
    // Ctrl+C / client shutdown.
}
return 0;
