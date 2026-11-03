using System.Globalization;
using WebGuard.Core.Scanning;

namespace WebGuard.Presentation.ViewModels;

/// <summary>Derives hints from file names and extensions only. Never reads file contents.</summary>
public static class InventoryInsights
{
    private static readonly string[] Lockfiles =
    [
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "packages.lock.json", "poetry.lock",
        "Pipfile.lock", "requirements.txt", "composer.lock", "go.sum", "Cargo.lock", "Gemfile.lock",
    ];

    private static readonly string[] SensitiveConfigNames =
    [
        "appsettings.json", "appsettings.development.json", "appsettings.production.json", "web.config",
        "secrets.json", "credentials.json", "config.json", "docker-compose.yml", "docker-compose.yaml",
    ];

    private static readonly string[] BinaryExtensions = [".exe", ".dll", ".so", ".dylib", ".bin", ".msi", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".jar"];

    private static readonly string[] KeyExtensions = [".pem", ".key", ".pfx", ".p12", ".jks", ".keystore"];

    public static IReadOnlyList<InventoryInsight> Analyze(IReadOnlyCollection<FileInventoryItem> files)
    {
        ArgumentNullException.ThrowIfNull(files);
        var list = new List<InventoryInsight>();
        if (files.Count == 0) return list;

        var names = files.Select(f => Path.GetFileName(f.RelativePath)).ToArray();

        var env = names.Count(n => n.Equals(".env", StringComparison.OrdinalIgnoreCase) || n.StartsWith(".env.", StringComparison.OrdinalIgnoreCase));
        var keys = files.Count(f => KeyExtensions.Contains(f.Extension, StringComparer.OrdinalIgnoreCase));
        if (env + keys > 0)
        {
            var parts = new List<string>(2);
            if (env > 0) parts.Add(Plural(env, "environment file"));
            if (keys > 0) parts.Add(Plural(keys, "key/certificate file"));
            list.Add(new("Possible secret containers", string.Join(" and ", parts) +
                " present. Gitleaks checks them for hardcoded secrets.", StatusTone.Danger));
        }

        var config = names.Count(n => SensitiveConfigNames.Contains(n, StringComparer.OrdinalIgnoreCase));
        if (config > 0)
            list.Add(new("Configuration files", Plural(config, "configuration file") +
                " (appsettings, web.config, compose) may hold connection strings or debug flags.", StatusTone.Warning));

        var executables = files.Count(f => BinaryExtensions.Contains(f.Extension, StringComparer.OrdinalIgnoreCase));
        if (executables > 0)
            list.Add(new("Executable or script content", Plural(executables, "binary or script file") +
                " inside a source tree. Candidates for hash lookup and YARA-X.", StatusTone.Warning));

        var locks = names.Count(n => Lockfiles.Contains(n, StringComparer.OrdinalIgnoreCase));
        if (locks > 0)
            list.Add(new("Dependency manifests", Plural(locks, "lockfile/manifest") +
                " detected. OSV-Scanner can audit them for vulnerable packages.", StatusTone.Info));

        var errors = files.Count(f => f.Status == FileScanStatus.Error);
        if (errors > 0)
            list.Add(new("Unreadable entries", Plural(errors, "entry") + " could not be read (permissions or locks).", StatusTone.Danger));

        if (list.Count == 0)
            list.Add(new("No notable file types", "No secret containers, binaries or lockfiles detected by name.", StatusTone.Success));

        return list;
    }

    private static string Plural(int count, string noun)
    {
        var word = count == 1 ? noun : noun.EndsWith('y') ? noun[..^1] + "ies" : noun + "s";
        return count.ToString("N0", CultureInfo.CurrentCulture) + " " + word;
    }
}
