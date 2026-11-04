using System.Text.RegularExpressions;

namespace WebGuard.Core.Findings;

/// <summary>
/// Removes credentials from free text (source excerpts, manifests) before it reaches an AI model or an MCP client.
/// Literal values of credential-like keys are masked while code references stay readable
/// (<c>token = "abc123"</c> is masked, <c>token = request.Headers["x"]</c> is kept).
/// </summary>
public static partial class SourceRedactor
{
    public const string Mask = "[REDACTED]";

    private const string Keyword =
        @"[A-Za-z0-9_.\-]*(?i:password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key|client[_\-]?secret|auth[_\-]?key|credential)[A-Za-z0-9_.\-]*";

    private static readonly string[] ConfigExtensions = [".env", ".ini", ".cfg", ".conf", ".config", ".properties", ".toml", ".yaml", ".yml", ".tfvars"];

    /// <summary>
    /// Redacts <paramref name="text"/>. Pass the file name so unquoted <c>KEY=value</c> lines are masked in
    /// configuration files (.env, .ini, YAML, …) without mangling ordinary code assignments elsewhere.
    /// </summary>
    public static string Redact(string? text, string? fileName = null)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        var result = PrivateKeyBlock().Replace(text, "-----BEGIN PRIVATE KEY-----" + Mask + "-----END PRIVATE KEY-----");
        result = KnownTokens().Replace(result, Mask);
        result = UrlCredentials().Replace(result, m => m.Groups["scheme"].Value + m.Groups["user"].Value + ":" + Mask + "@");
        result = QuotedSecret().Replace(result, m => m.Groups["key"].Value + m.Groups["sep"].Value + m.Groups["q"].Value + Mask + m.Groups["q"].Value);
        result = ConnectionStringSecret().Replace(result, m => m.Groups["key"].Value + m.Groups["sep"].Value + Mask);
        if (IsConfigFile(fileName))
            result = ConfigLineSecret().Replace(result, m => m.Groups["key"].Value + m.Groups["sep"].Value + Mask);
        return result;
    }

    public static bool IsConfigFile(string? fileName)
    {
        if (string.IsNullOrEmpty(fileName)) return false;
        var name = Path.GetFileName(fileName);
        return name.StartsWith(".env", StringComparison.OrdinalIgnoreCase) ||
               ConfigExtensions.Contains(Path.GetExtension(name), StringComparer.OrdinalIgnoreCase);
    }

    [GeneratedRegex(@"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")]
    private static partial Regex PrivateKeyBlock();

    // AWS, GitHub, Slack, Stripe, Google, SendGrid, npm tokens and JWTs, wherever they appear.
    [GeneratedRegex(@"\b(?:(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|xox[abprs]-[A-Za-z0-9-]{10,}|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_\-]{35}|SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}|npm_[A-Za-z0-9]{36}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})")]
    private static partial Regex KnownTokens();

    [GeneratedRegex(@"(?<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)(?<user>[^:/\s@]+):(?<pass>[^@/\s]+)@")]
    private static partial Regex UrlCredentials();

    // apiKey = "value", "password": "value", secret: 'value', 'db_password' => 'value', define('API_KEY', 'value')
    [GeneratedRegex(@"(?<key>" + Keyword + @")(?<sep>[""']?\s*(?:=>|[:=,])\s*)(?<q>[""'])(?<value>[^""'\r\n]{3,})\k<q>")]
    private static partial Regex QuotedSecret();

    // Server=x;Password=value;  /  "...;pwd=value"
    [GeneratedRegex(@"(?<key>(?:^|[;""'\s])(?i:password|pwd))(?<sep>\s*=\s*)(?<value>[^;""'\r\n]+)", RegexOptions.Multiline)]
    private static partial Regex ConnectionStringSecret();

    // .env / ini / YAML lines:  DB_PASSWORD=value   api_key: value   export TOKEN=value
    [GeneratedRegex(@"^(?<key>[ \t]*(?:export[ \t]+)?" + Keyword + @")(?<sep>[ \t]*[:=][ \t]*)(?<value>[^\s""'#][^\r\n#]*)", RegexOptions.Multiline)]
    private static partial Regex ConfigLineSecret();
}
