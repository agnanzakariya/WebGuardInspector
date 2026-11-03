using System.Text.Json;
using System.Text.Json.Nodes;
using WebGuard.Core.Findings;

namespace WebGuard.Mcp;

/// <summary>
/// Append-only JSON Lines record of every tool call (allowed, denied or failed): time, tool, redacted arguments,
/// outcome and duration. Lives under %LOCALAPPDATA%\WebGuardInspector by default.
/// </summary>
public sealed class McpAuditLog(string path, TimeProvider? timeProvider = null)
{
    private readonly Lock _gate = new();
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WebGuardInspector", "mcp-audit.jsonl");

    public string FilePath { get; } = path;

    public void Record(string root, string tool, JsonObject arguments, string outcome, TimeSpan duration, string? detail = null)
    {
        var redacted = new JsonObject();
        foreach (var (key, value) in arguments)
        {
            redacted[key] = value is JsonValue v && v.TryGetValue<string>(out var s) ? SourceRedactor.Redact(s) : value?.DeepClone();
        }
        var entry = new JsonObject
        {
            ["timeUtc"] = _time.GetUtcNow().ToString("O"),
            ["root"] = root,
            ["tool"] = tool,
            ["arguments"] = redacted,
            ["outcome"] = outcome,
            ["durationMs"] = Math.Round(duration.TotalMilliseconds),
            ["detail"] = detail is null ? null : SourceRedactor.Redact(detail.Length > 300 ? detail[..300] : detail),
        };
        var line = entry.ToJsonString(new JsonSerializerOptions { WriteIndented = false }) + Environment.NewLine;
        lock (_gate)
        {
            try
            {
                var directory = Path.GetDirectoryName(FilePath);
                if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
                File.AppendAllText(FilePath, line);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Auditing must not break the tool call; report on stderr, which MCP clients surface as server logs.
                Console.Error.WriteLine("webguard-mcp: could not write audit log: " + ex.Message);
            }
        }
    }
}
