using System.Text.RegularExpressions;
using WebGuard.Core.Findings;

namespace WebGuard.Core.Fixing;

/// <summary>
/// How to fix a vulnerable dependency reported in a lockfile. Lockfiles are generated, so the fix is a version
/// constraint in the manifest next to it (when needed) followed by the package manager command that regenerates the
/// lockfile. Azura shows that command for the person to run; it never runs package managers itself, because install
/// scripts of a third-party package would run with it.
/// </summary>
/// <param name="ManifestPath">Manifest relative to the project root (may not exist, e.g. go.mod next to go.sum).</param>
public sealed partial record DependencyFixPlan(
    string Ecosystem,
    string Package,
    string InstalledVersion,
    IReadOnlyList<string> FixedVersions,
    string LockfilePath,
    string ManifestPath,
    string Command)
{
    private sealed record Manager(string Lockfile, string Manifest, Func<string, string?, string> Command);

    private static readonly Manager[] Managers =
    [
        new("composer.lock", "composer.json", (p, _) => $"composer update {p} --with-all-dependencies"),
        new("package-lock.json", "package.json", (p, v) => $"npm install {p}@{v ?? "latest"}"),
        new("yarn.lock", "package.json", (p, v) => $"yarn upgrade {p}@{v ?? "latest"}"),
        new("pnpm-lock.yaml", "package.json", (p, v) => $"pnpm update {p}@{v ?? "latest"}"),
        new("bun.lock", "package.json", (p, v) => $"bun update {p}@{v ?? "latest"}"),
        new("poetry.lock", "pyproject.toml", (p, _) => $"poetry update {p}"),
        new("Pipfile.lock", "Pipfile", (p, _) => $"pipenv update {p}"),
        new("uv.lock", "pyproject.toml", (p, _) => $"uv lock --upgrade-package {p}"),
        new("Gemfile.lock", "Gemfile", (p, _) => $"bundle update {p}"),
        new("Cargo.lock", "Cargo.toml", (p, v) => v is null ? $"cargo update -p {p}" : $"cargo update -p {p} --precise {v}"),
        new("go.sum", "go.mod", (p, v) => $"go get {p}@{(v is null ? "latest" : "v" + v.TrimStart('v'))} && go mod tidy"),
        new("mix.lock", "mix.exs", (p, _) => $"mix deps.update {p}"),
        new("pubspec.lock", "pubspec.yaml", (p, _) => $"dart pub upgrade {p}"),
    ];

    /// <summary>True when the finding is a dependency vulnerability reported in a lockfile Azura knows.</summary>
    public static bool TryCreate(SecurityFinding finding, out DependencyFixPlan plan)
    {
        ArgumentNullException.ThrowIfNull(finding);
        plan = null!;
        if (finding.Category != FindingCategory.VulnerableDependency) return false;
        var lockfile = finding.Location.RelativePath;
        var manager = Managers.FirstOrDefault(m => Path.GetFileName(lockfile).Equals(m.Lockfile, StringComparison.OrdinalIgnoreCase));
        var coordinate = finding.Evidence.FirstOrDefault(e => e.Kind == "package")?.RedactedSnippet;
        if (manager is null || coordinate is null) return false;

        // "Packagist/laravel/framework@11.51.0", "npm/@scope/pkg@1.2.3": ecosystem, then name@version (last '@').
        var slash = coordinate.IndexOf('/', StringComparison.Ordinal);
        var at = coordinate.LastIndexOf('@');
        if (slash <= 0 || at <= slash + 1) return false;
        var package = coordinate[(slash + 1)..at];
        var version = coordinate[(at + 1)..];
        var fixedVersions = FixedIn().Match(finding.Remediation ?? string.Empty) is { Success: true } m
            ? m.Groups["v"].Value.Split(" or ", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : [];
        var target = PickFixedVersion(version, fixedVersions);
        var folder = Path.GetDirectoryName(lockfile) ?? string.Empty;
        plan = new DependencyFixPlan(coordinate[..slash], package, version, fixedVersions, lockfile,
            Path.Combine(folder, manager.Manifest), manager.Command(package, target));
        return true;
    }

    /// <summary>The lowest fixed version not older than the installed one (same major line when possible).</summary>
    private static string? PickFixedVersion(string installed, string[] fixedVersions)
    {
        var current = Updates.AppVersion.Parse(installed);
        var parsed = fixedVersions.Select(v => (Text: v, Version: Updates.AppVersion.Parse(v))).Where(v => v.Version is not null).ToArray();
        if (parsed.Length == 0) return fixedVersions.Length > 0 ? fixedVersions[0] : null;
        var candidates = current is null ? parsed : parsed.Where(v => v.Version! >= current).ToArray();
        var sameMajor = current is null ? [] : candidates.Where(v => v.Version!.Major == current.Major).ToArray();
        var pick = (sameMajor.Length > 0 ? sameMajor : candidates.Length > 0 ? candidates : parsed).OrderBy(v => v.Version).First();
        return pick.Text;
    }

    [GeneratedRegex(@"^Upgrade \S+ to (?<v>.+?) or later\.?$")]
    private static partial Regex FixedIn();
}
