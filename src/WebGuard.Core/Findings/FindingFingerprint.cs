using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace WebGuard.Core.Findings;

/// <summary>
/// Stable identity of a finding across scans, used for deduplication and regression tracking.
/// Based on engine, rule, normalized path and whitespace-normalized code; deliberately excludes line numbers
/// so that unrelated edits above the finding do not create a "new" finding.
/// </summary>
public static partial class FindingFingerprint
{
    public static string Compute(string engineId, string ruleId, string relativePath, string? codeSnippet)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(engineId);
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleId);
        ArgumentNullException.ThrowIfNull(relativePath);

        var normalizedPath = relativePath.Replace('\\', '/').Trim('/').ToUpperInvariant();
        var normalizedCode = codeSnippet is null ? string.Empty : Whitespace().Replace(codeSnippet, " ").Trim();
        var material = string.Join('\u001F', engineId.Trim().ToUpperInvariant(), ruleId.Trim(), normalizedPath, normalizedCode);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        return "wgf1:" + Convert.ToHexStringLower(hash);
    }

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();
}
