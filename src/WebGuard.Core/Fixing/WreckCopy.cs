using System.Globalization;
using System.Text;
using WebGuard.Core.Scanning;

namespace WebGuard.Core.Fixing;

/// <summary>
/// The "wreck" copy of a file that was fixed: the vulnerable version, commented out line by line, renamed to
/// <c>name.ext.yyyyMMdd-HHmmss.wreck</c> and kept under <c>&lt;project&gt;\wreck\</c> with the original sub-folders.
/// The extra extension stops web servers and interpreters from running it, the comments keep it inert even if it is
/// renamed back, and the folder is never scanned (<see cref="ScanOptions.WreckFolder"/>). It is for people to read;
/// Undo uses the exact backup instead.
/// </summary>
public static class WreckCopy
{
    private static readonly HashSet<string> SlashSlash = new(StringComparer.OrdinalIgnoreCase)
    {
        ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps", ".inc", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
        ".cs", ".java", ".kt", ".kts", ".go", ".c", ".h", ".cc", ".cpp", ".hpp", ".swift", ".rs", ".dart", ".scss", ".less", ".groovy", ".scala",
    };

    private static readonly HashSet<string> Hash = new(StringComparer.OrdinalIgnoreCase)
    {
        ".py", ".rb", ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".psd1", ".pl", ".pm", ".r", ".yml", ".yaml", ".toml", ".conf",
        ".cfg", ".properties", ".env", ".htaccess", ".dockerfile", ".tf", ".tfvars", ".mk",
    };

    private static readonly HashSet<string> Php = new(StringComparer.OrdinalIgnoreCase)
    {
        ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps", ".inc",
    };

    private static readonly HashSet<string> Markup = new(StringComparer.OrdinalIgnoreCase)
    {
        ".html", ".htm", ".xhtml", ".xml", ".svg", ".vue", ".svelte", ".aspx", ".ascx", ".cshtml", ".razor", ".jsp", ".xaml",
    };

    /// <summary>Where the wreck copy of <paramref name="relativePath"/> goes; a counter is added if the name is taken.</summary>
    public static string PathFor(ProjectScope scope, string relativePath, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentException.ThrowIfNullOrEmpty(relativePath);
        var relative = relativePath.Replace('/', Path.DirectorySeparatorChar);
        var folder = Path.Combine(scope.Root, ScanOptions.WreckFolder, Path.GetDirectoryName(relative) ?? string.Empty);
        var stamp = at.ToLocalTime().ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var name = Path.GetFileName(relative);
        var path = Path.Combine(folder, $"{name}.{stamp}.wreck");
        for (var n = 2; File.Exists(path); n++) path = Path.Combine(folder, $"{name}.{stamp}-{n}.wreck");
        return path;
    }

    /// <summary>Header plus every line of <paramref name="text"/> ("\n" line endings) commented out for the file's language.</summary>
    public static string Render(string relativePath, string text, IEnumerable<string> header)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(header);
        var extension = ExtensionOf(relativePath);
        var php = Php.Contains(extension);
        var sb = new StringBuilder();
        foreach (var line in header) sb.Append(Comment(line, extension)).Append('\n');
        if (php) sb.Append(Comment("PHP tags are defused in this copy: \"<?\" is written as \"< ?\" and \"?>\" as \"? >\".", extension)).Append('\n');
        sb.Append(Comment(new string('-', 100), extension)).Append('\n');
        var lines = text.Split('\n');
        // The newline that ends the file is not a line of its own.
        foreach (var raw in text.EndsWith('\n') ? lines[..^1] : lines)
        {
            // A PHP "//" comment ends at "?>", so the tags themselves are broken as well.
            var line = php ? raw.Replace("<?", "< ?", StringComparison.Ordinal).Replace("?>", "? >", StringComparison.Ordinal) : raw;
            sb.Append(Comment(line, extension)).Append('\n');
        }
        return sb.ToString();
    }

    /// <summary>One commented line in the syntax of the file type (line comments where the language has them).</summary>
    public static string Comment(string line, string extension)
    {
        ArgumentNullException.ThrowIfNull(line);
        if (SlashSlash.Contains(extension)) return "// " + line;
        if (Hash.Contains(extension)) return "# " + line;
        if (Markup.Contains(extension)) return "<!-- " + line.Replace("--", "- -", StringComparison.Ordinal) + " -->";
        return extension.ToUpperInvariant() switch
        {
            ".CSS" => "/* " + line.Replace("*/", "* /", StringComparison.Ordinal) + " */",
            ".SQL" or ".LUA" or ".HS" => "-- " + line,
            ".INI" => "; " + line,
            ".BAT" or ".CMD" => "REM " + line,
            ".VB" or ".VBS" or ".ASP" => "' " + line,
            _ => "# " + line,
        };
    }

    /// <summary>Extension used to pick the comment style; dot-files such as ".htaccess" and ".env" count as their own type.</summary>
    private static string ExtensionOf(string relativePath)
    {
        var name = Path.GetFileName(relativePath ?? string.Empty);
        if (name.StartsWith(".env", StringComparison.OrdinalIgnoreCase)) return ".env";
        if (name.Equals(".htaccess", StringComparison.OrdinalIgnoreCase)) return ".htaccess";
        if (name.Equals("Dockerfile", StringComparison.OrdinalIgnoreCase)) return ".dockerfile";
        if (name.Equals("Makefile", StringComparison.OrdinalIgnoreCase)) return ".mk";
        return Path.GetExtension(name);
    }
}
