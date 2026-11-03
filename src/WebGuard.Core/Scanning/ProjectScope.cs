namespace WebGuard.Core.Scanning;

/// <summary>
/// The user-approved folder that AI and MCP tools may read. Paths are resolved against it and rejected when they
/// escape it ("..", absolute paths elsewhere) or pass through a symlink/junction, mirroring the scanner's rules.
/// </summary>
public sealed class ProjectScope
{
    public ProjectScope(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        var full = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException($"Folder not found: {root}");
        Root = full;
    }

    public string Root { get; }

    /// <summary>Resolves <paramref name="path"/> (relative to the root, or absolute inside it) to a full path.</summary>
    public bool TryResolve(string? path, out string fullPath, out string error)
    {
        fullPath = string.Empty;
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(path) || path.Contains('\0', StringComparison.Ordinal))
        {
            error = "A path inside the project is required.";
            return false;
        }

        var candidate = Path.GetFullPath(path.Trim(), Root);
        var inside = candidate.Equals(Root, StringComparison.OrdinalIgnoreCase) ||
                     candidate.StartsWith(Root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        if (!inside)
        {
            error = "Path is outside the approved project folder.";
            return false;
        }

        // Walk from the root down so a junction anywhere on the way is caught, as the scanner never follows them.
        var current = Root;
        foreach (var part in Path.GetRelativePath(Root, candidate).Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == ".") continue;
            current = Path.Combine(current, part);
            if ((File.Exists(current) || Directory.Exists(current)) && File.GetAttributes(current).HasFlag(FileAttributes.ReparsePoint))
            {
                error = "Path goes through a symbolic link or junction, which is not followed.";
                return false;
            }
        }

        fullPath = candidate;
        return true;
    }

    public string ToRelative(string fullPath) => Path.GetRelativePath(Root, fullPath);
}
