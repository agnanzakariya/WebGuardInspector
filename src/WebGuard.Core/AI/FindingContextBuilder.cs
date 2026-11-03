using System.Globalization;
using System.Text;
using WebGuard.Core.Findings;
using WebGuard.Core.Scanning;

namespace WebGuard.Core.AI;

/// <summary>
/// Builds the context an AI model sees for one finding: a line-numbered, secret-redacted excerpt around the location
/// (resolved strictly inside the approved project folder) and other occurrences of the same rule.
/// Binary files are never excerpted.
/// </summary>
public static class FindingContextBuilder
{
    public const int DefaultRadius = 15;
    public const int MaxExcerptChars = 6000;
    private const long MaxFileBytes = 2 * 1024 * 1024;

    public static FindingContext Build(ProjectScope scope, SecurityFinding finding, IEnumerable<SecurityFinding> allFindings, int radius = DefaultRadius)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(finding);
        ArgumentNullException.ThrowIfNull(allFindings);
        var similar = allFindings
            .Where(f => f.Id != finding.Id && f.RuleId == finding.RuleId)
            .Take(5)
            .ToArray();
        return new FindingContext(finding, Excerpt(scope, finding, radius), similar);
    }

    public static string Excerpt(ProjectScope scope, SecurityFinding finding, int radius = DefaultRadius)
    {
        ArgumentNullException.ThrowIfNull(finding);
        var location = finding.Location;
        return Excerpt(scope, location.RelativePath, location.StartLine, Math.Max(location.StartLine, location.EndLine), radius,
            lines => LocateWithoutLine(lines, finding));
    }

    /// <summary>Line-numbered, redacted excerpt of <paramref name="relativePath"/> around lines start..end (1-based).</summary>
    public static string Excerpt(ProjectScope scope, string relativePath, int startLine, int endLine, int radius,
        Func<string[], (int Start, int End)>? locateWhenNoLine = null)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (!scope.TryResolve(relativePath, out var path, out var error)) return $"(source not available: {error})";
        if (!File.Exists(path)) return "(source file not found)";
        var info = new FileInfo(path);
        if (info.Length > MaxFileBytes) return $"(file is {info.Length / 1024:N0} KB; too large to excerpt)";

        string[] lines;
        try
        {
            var bytes = File.ReadAllBytes(path);
            if (Array.IndexOf(bytes, (byte)0, 0, Math.Min(bytes.Length, 8192)) >= 0) return "(binary file; content is not shared with the model)";
            lines = Encoding.UTF8.GetString(bytes).Split('\n');
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return "(source could not be read: " + ex.Message + ")";
        }

        var (start, end) = startLine > 0
            ? (Math.Min(startLine, lines.Length), Math.Min(Math.Max(startLine, endLine), lines.Length))
            : locateWhenNoLine?.Invoke(lines) ?? (1, Math.Min(lines.Length, 1));
        var from = Math.Max(1, start - radius);
        var to = Math.Min(lines.Length, end + radius);

        var builder = new StringBuilder();
        for (var n = from; n <= to; n++)
        {
            var marker = n >= start && n <= end && start > 0 ? ">" : " ";
            builder.Append(marker).Append(n.ToString(CultureInfo.InvariantCulture).PadLeft(5)).Append(" | ").Append(lines[n - 1].TrimEnd('\r')).Append('\n');
        }
        var excerpt = SourceRedactor.Redact(builder.ToString(), path);
        return excerpt.Length > MaxExcerptChars ? excerpt[..MaxExcerptChars] + "\n(… truncated)" : excerpt;
    }

    /// <summary>For line-less findings (dependencies, signatures) point at the package name, else the top of the file.</summary>
    private static (int Start, int End) LocateWithoutLine(string[] lines, SecurityFinding finding)
    {
        var coordinate = finding.Evidence.FirstOrDefault(e => e.Kind == "package")?.RedactedSnippet;
        var name = coordinate?.Split('/', 2).LastOrDefault()?.Split('@')[0];
        if (!string.IsNullOrEmpty(name))
        {
            var shortName = name.Split(':')[^1];
            for (var i = 0; i < lines.Length; i++)
            {
                if (lines[i].Contains(shortName, StringComparison.OrdinalIgnoreCase)) return (i + 1, i + 1);
            }
        }
        return (1, Math.Min(lines.Length, 1));
    }
}
