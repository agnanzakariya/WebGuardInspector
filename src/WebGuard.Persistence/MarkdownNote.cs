using System.Globalization;
using System.Text;

namespace WebGuard.Persistence;

/// <summary>
/// A Markdown note with YAML frontmatter (Obsidian "properties") and WebGuard-managed blocks delimited by
/// <c>&lt;!-- webguard:name --&gt;</c> … <c>&lt;!-- /webguard:name --&gt;</c>. Everything else — properties a person
/// added, text outside the blocks — is preserved byte for byte when the note is rewritten.
/// </summary>
internal sealed class MarkdownNote
{
    private readonly List<KeyValuePair<string, string>> _properties = [];

    private MarkdownNote(string body) => Body = body;

    public string Body { get; private set; }

    public static MarkdownNote Create(string body) => new(body);

    public static MarkdownNote Parse(string text)
    {
        text = text.Replace("\r\n", "\n", StringComparison.Ordinal);
        if (!text.StartsWith("---\n", StringComparison.Ordinal)) return new MarkdownNote(text);
        var end = text.IndexOf("\n---", 3, StringComparison.Ordinal);
        if (end < 0) return new MarkdownNote(text);

        var note = new MarkdownNote(text[(end + 4)..].TrimStart('\n'));
        foreach (var line in text[4..end].Split('\n'))
        {
            var colon = line.IndexOf(':', StringComparison.Ordinal);
            var isKey = line.Length > 0 && !char.IsWhiteSpace(line[0]) && line[0] != '-' && colon > 0;
            if (isKey)
                note._properties.Add(new(line[..colon], line[(colon + 1)..]));
            else if (note._properties.Count > 0)
            {
                // Continuation of a multi-line value (YAML list items, folded text).
                var last = note._properties[^1];
                note._properties[^1] = new(last.Key, last.Value + "\n" + line);
            }
        }
        return note;
    }

    public string Render()
    {
        var sb = new StringBuilder("---\n");
        foreach (var (key, raw) in _properties) sb.Append(key).Append(':').Append(raw).Append('\n');
        sb.Append("---\n").Append(Body.TrimEnd('\n')).Append('\n');
        return sb.ToString();
    }

    /// <summary>Property value with YAML quotes removed; null when absent.</summary>
    public string? Get(string key)
    {
        var raw = _properties.FirstOrDefault(p => p.Key == key).Value;
        if (raw is null) return null;
        var value = raw.Trim();
        return value.Length >= 2 && (value[0] == '"' && value[^1] == '"' || value[0] == '\'' && value[^1] == '\'')
            ? value[1..^1].Replace("\\\"", "\"", StringComparison.Ordinal).Replace("\\\\", "\\", StringComparison.Ordinal)
            : value;
    }

    /// <summary>Items of a list property, whether written inline (<c>[a, b]</c>) or as a YAML block list.</summary>
    public IReadOnlyList<string> GetList(string key)
    {
        var raw = _properties.FirstOrDefault(p => p.Key == key).Value;
        if (raw is null) return [];
        var trimmed = raw.Trim();
        IEnumerable<string> items = trimmed.StartsWith('[') && trimmed.EndsWith(']')
            ? trimmed[1..^1].Split(',')
            : raw.Split('\n').Select(l => l.Trim()).Where(l => l.StartsWith("- ", StringComparison.Ordinal)).Select(l => l[2..]);
        return items.Select(i => i.Trim().Trim('"', '\'')).Where(i => i.Length > 0).ToArray();
    }

    public void SetString(string key, string? value) => SetRaw(key, value is null ? string.Empty : " " + Quote(value));
    public void SetNumber(string key, double value) => SetRaw(key, " " + value.ToString("0.###", CultureInfo.InvariantCulture));
    public void SetNumber(string key, int value) => SetRaw(key, " " + value.ToString(CultureInfo.InvariantCulture));
    public void SetDate(string key, DateTimeOffset value) => SetRaw(key, " " + value.ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture));
    public void SetPlain(string key, string value) => SetRaw(key, " " + value);
    public void SetList(string key, IEnumerable<string> values) => SetRaw(key, " [" + string.Join(", ", values.Select(Quote)) + "]");

    public bool Has(string key) => _properties.Any(p => p.Key == key);

    public string? GetBlock(string name)
    {
        var (start, end) = FindBlock(name);
        return start < 0 ? null : Body[start..end].Trim('\n');
    }

    /// <summary>Replaces a managed block; when a person deleted it, it is re-added before the "My notes" section (or at the end).</summary>
    public void SetBlock(string name, string content)
    {
        var (start, end) = FindBlock(name);
        var inner = "\n" + content.Trim('\n') + "\n";
        if (start >= 0)
        {
            Body = Body[..start] + inner + Body[end..];
            return;
        }
        var block = $"<!-- webguard:{name} -->{inner}<!-- /webguard:{name} -->\n";
        var notes = Body.IndexOf("\n## My notes", StringComparison.Ordinal);
        Body = notes >= 0 ? Body[..(notes + 1)] + block + "\n" + Body[(notes + 1)..] : Body.TrimEnd('\n') + "\n\n" + block;
    }

    public static string Quote(string value) =>
        "\"" + value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\r", " ", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal) + "\"";

    private void SetRaw(string key, string raw)
    {
        var index = _properties.FindIndex(p => p.Key == key);
        if (index >= 0) _properties[index] = new(key, raw);
        else _properties.Add(new(key, raw));
    }

    private (int Start, int End) FindBlock(string name)
    {
        var open = $"<!-- webguard:{name} -->";
        var close = $"<!-- /webguard:{name} -->";
        var start = Body.IndexOf(open, StringComparison.Ordinal);
        if (start < 0) return (-1, -1);
        var end = Body.IndexOf(close, start, StringComparison.Ordinal);
        return end < 0 ? (-1, -1) : (start + open.Length, end);
    }
}
