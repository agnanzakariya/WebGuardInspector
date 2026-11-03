namespace WebGuard.Detection;

/// <summary>
/// Finds an engine executable when none is configured. Only fully qualified PATH entries and well-known install
/// folders are searched, only .exe files are accepted on Windows (no .cmd/.bat), and the result is an absolute path.
/// </summary>
public static class ExecutableLocator
{
    public static string? Find(IEnumerable<string> names, IEnumerable<string>? searchDirectories = null)
    {
        ArgumentNullException.ThrowIfNull(names);
        var fileNames = names
            .Select(n => OperatingSystem.IsWindows() && !n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? n + ".exe" : n)
            .ToArray();

        foreach (var directory in searchDirectories ?? DefaultSearchDirectories())
        {
            if (string.IsNullOrWhiteSpace(directory) || !Path.IsPathFullyQualified(directory)) continue;
            foreach (var name in fileNames)
            {
                var candidate = Path.Combine(directory, name);
                if (File.Exists(candidate)) return Path.GetFullPath(candidate);
            }
        }
        return null;
    }

    public static IEnumerable<string> DefaultSearchDirectories()
    {
        // The persisted User/Machine PATH is read as well, so a tool installed while the app is running
        // (e.g. winget adds its package folder to the User PATH) is found without restarting.
        var paths = new List<string?> { Environment.GetEnvironmentVariable("PATH") };
        if (OperatingSystem.IsWindows())
        {
            paths.Add(Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.User));
            paths.Add(Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.Machine));
        }
        foreach (var path in paths)
        {
            foreach (var entry in (path ?? string.Empty).Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                yield return Environment.ExpandEnvironmentVariables(entry.Trim('"'));
        }

        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        yield return Path.Combine(local, "Microsoft", "WinGet", "Links");
        yield return Path.Combine(home, "scoop", "shims");
        yield return Path.Combine(home, "go", "bin");
        yield return Path.Combine(home, ".cargo", "bin");
        yield return Path.Combine(home, ".local", "bin");

        // "pip install --user" (e.g. Semgrep) puts scripts under %APPDATA%\Python\PythonXY\Scripts, which is often not on PATH.
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        foreach (var pythonRoot in new[] { Path.Combine(appData, "Python"), Path.Combine(local, "Programs", "Python") })
        {
            if (!Directory.Exists(pythonRoot)) continue;
            foreach (var version in Directory.EnumerateDirectories(pythonRoot, "Python3*").OrderDescending(StringComparer.OrdinalIgnoreCase))
                yield return Path.Combine(version, "Scripts");
        }
        yield return Path.Combine(programFiles, "WebGuardInspector", "tools");
        yield return Path.Combine(AppContext.BaseDirectory, "tools");
    }
}
