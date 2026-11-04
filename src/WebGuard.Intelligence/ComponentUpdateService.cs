using System.IO.Compression;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using WebGuard.Core.Detection;
using WebGuard.Core.Updates;

namespace WebGuard.Intelligence;

/// <summary>
/// Finds newer versions of the security engines and Claude Code and updates each one the way it was installed:
/// <list type="bullet">
/// <item>exe in the app's tools folder: the official GitHub release asset is downloaded, its SHA-256 checked against
/// the digest GitHub publishes for the asset, and the exe replaced;</item>
/// <item>installed with winget: <c>winget upgrade --id …</c>;</item>
/// <item>Semgrep installed with pip: <c>python -m pip install --upgrade semgrep</c> with the Python that owns it;</item>
/// <item>Claude Code: <c>claude update</c>.</item>
/// </list>
/// Version lookups only read public metadata (GitHub releases, PyPI, npm); no project data is sent.
/// </summary>
public sealed partial class ComponentUpdateService(HttpClient http, IExternalProcessRunner runner, string bundledToolsFolder, Func<string?> locateWinget)
    : IComponentUpdater
{
    private static readonly TimeSpan LookupTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan UpdateTimeout = TimeSpan.FromMinutes(10);
    private const long MaxDownloadBytes = 300L * 1024 * 1024;

    private sealed record Spec(string Id, string ExeName, string? GitHubRepo = null, string? WingetId = null, Regex? Asset = null,
        string? PyPiPackage = null, string? NpmPackage = null);

    private static readonly Spec[] Specs =
    [
        new("semgrep", "semgrep.exe", PyPiPackage: "semgrep"),
        new("gitleaks", "gitleaks.exe", "gitleaks/gitleaks", "Gitleaks.Gitleaks", GitleaksAsset()),
        new("osv-scanner", "osv-scanner.exe", "google/osv-scanner", "Google.OSVScanner", OsvAsset()),
        new("yara-x", "yr.exe", "VirusTotal/yara-x", "VirusTotal.YARA-X", YaraAsset()),
        new("claude-code", "claude.exe", NpmPackage: "@anthropic-ai/claude-code"),
    ];

    /// <summary>Components this service knows how to check.</summary>
    public static IReadOnlyCollection<string> KnownIds { get; } = Specs.Select(s => s.Id).ToArray();

    public async Task<IReadOnlyList<ComponentState>> CheckAsync(IReadOnlyList<InstalledComponent> installed, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(installed);
        var tasks = installed.Select(c => CheckOneAsync(c, cancellationToken));
        return await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private async Task<ComponentState> CheckOneAsync(InstalledComponent component, CancellationToken cancellationToken)
    {
        var spec = Specs.FirstOrDefault(s => s.Id == component.Id);
        var source = DetectSource(component, spec);
        if (spec is null) return new ComponentState(component.Id, component.Name, component.Version, null, component.ExecutablePath, source, false, "Not checked.");
        string? latest = null;
        string? note = null;
        try
        {
            latest = await LatestVersionAsync(spec, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException && !cancellationToken.IsCancellationRequested)
        {
            note = "Latest version unknown: " + (ex is TaskCanceledException ? "no answer in time." : ex.Message);
        }
        var newer = latest is not null && source != ComponentSource.Missing && AppVersion.IsNewer(latest, component.Version ?? "0");
        note ??= source switch
        {
            ComponentSource.Missing => "Not installed. Install it (see README) or set its path in Settings.",
            ComponentSource.Manual when newer => "Installed outside Azura's known locations; update it the way you installed it.",
            _ => null,
        };
        return new ComponentState(component.Id, component.Name, component.Version, latest, component.ExecutablePath, source, newer, note);
    }

    private async Task<string?> LatestVersionAsync(Spec spec, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(LookupTimeout);
        if (spec.GitHubRepo is not null)
        {
            using var doc = await GitHubReleaseAsync(spec.GitHubRepo, timeout.Token).ConfigureAwait(false);
            return Normalise(doc.RootElement.GetProperty("tag_name").GetString());
        }
        if (spec.PyPiPackage is not null)
        {
            using var doc = JsonDocument.Parse(await http.GetStringAsync(new Uri($"https://pypi.org/pypi/{spec.PyPiPackage}/json"), timeout.Token).ConfigureAwait(false));
            return Normalise(doc.RootElement.GetProperty("info").GetProperty("version").GetString());
        }
        if (spec.NpmPackage is not null)
        {
            using var doc = JsonDocument.Parse(await http.GetStringAsync(new Uri($"https://registry.npmjs.org/{spec.NpmPackage}/latest"), timeout.Token).ConfigureAwait(false));
            return Normalise(doc.RootElement.GetProperty("version").GetString());
        }
        return null;
    }

    public async Task<string> UpdateAsync(ComponentState component, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(component);
        var spec = Specs.FirstOrDefault(s => s.Id == component.Id) ?? throw new InvalidOperationException($"{component.Name} cannot be updated from Azura.");
        if (!component.CanUpdate) throw new InvalidOperationException($"No update to install for {component.Name}.");
        return component.Source switch
        {
            ComponentSource.Bundled => await UpdateBundledAsync(spec, component, progress, cancellationToken).ConfigureAwait(false),
            ComponentSource.Winget => await UpdateWithWingetAsync(spec, component, progress, cancellationToken).ConfigureAwait(false),
            ComponentSource.Pip => await UpdateWithPipAsync(spec, component, progress, cancellationToken).ConfigureAwait(false),
            ComponentSource.ClaudeUpdater => await UpdateClaudeAsync(component, progress, cancellationToken).ConfigureAwait(false),
            _ => throw new InvalidOperationException($"{component.Name} was not installed by a method Azura can update."),
        };
    }

    // ---- Bundled exe ---------------------------------------------------------------------------------------------

    private async Task<string> UpdateBundledAsync(Spec spec, ComponentState component, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        var target = component.ExecutablePath ?? throw new InvalidOperationException("The executable path is unknown.");
        progress?.Report($"Looking up the {component.Name} release on GitHub…");
        using var release = await GitHubReleaseAsync(spec.GitHubRepo!, cancellationToken).ConfigureAwait(false);
        var asset = release.RootElement.GetProperty("assets").EnumerateArray()
            .FirstOrDefault(a => spec.Asset!.IsMatch(a.GetProperty("name").GetString() ?? string.Empty));
        if (asset.ValueKind != JsonValueKind.Object) throw new InvalidOperationException($"The latest {component.Name} release has no Windows x64 download.");
        var name = asset.GetProperty("name").GetString()!;
        var url = new Uri(asset.GetProperty("browser_download_url").GetString()!);
        if (!IsReleaseDownload(url, spec.GitHubRepo!)) throw new InvalidOperationException("The download URL is not an official release asset.");
        var digest = asset.TryGetProperty("digest", out var d) && d.GetString() is { } dg && dg.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)
            ? dg["sha256:".Length..].ToLowerInvariant()
            : throw new InvalidOperationException("GitHub published no SHA-256 for this download, so it is not installed automatically.");

        progress?.Report($"Downloading {name}…");
        var bytes = await DownloadAsync(url, cancellationToken).ConfigureAwait(false);
        var actual = Convert.ToHexStringLower(SHA256.HashData(bytes));
        if (actual != digest) throw new InvalidOperationException($"The download does not match GitHub's SHA-256 (expected {digest}, got {actual}); nothing was changed.");

        byte[] exe;
        if (name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
        {
            using var zip = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
            var entry = zip.Entries.FirstOrDefault(e => e.Name.Equals(spec.ExeName, StringComparison.OrdinalIgnoreCase))
                        ?? throw new InvalidOperationException($"{spec.ExeName} was not found in {name}.");
            using var ms = new MemoryStream();
            await using (var s = entry.Open()) await s.CopyToAsync(ms, cancellationToken).ConfigureAwait(false);
            exe = ms.ToArray();
        }
        else
        {
            exe = bytes;
        }

        progress?.Report($"Replacing {Path.GetFileName(target)}…");
        var staged = target + ".new";
        try
        {
            await File.WriteAllBytesAsync(staged, exe, cancellationToken).ConfigureAwait(false);
            var backup = target + ".old";
            File.Copy(target, backup, overwrite: true);
            File.Move(staged, target, overwrite: true);
            File.Delete(backup);
        }
        catch (UnauthorizedAccessException)
        {
            if (File.Exists(staged)) File.Delete(staged);
            throw new InvalidOperationException("The app folder is read-only (installed for all users). Run Azura once as administrator to update, " +
                                                "or install the tool with winget and Azura will use that copy.");
        }
        var version = await RunAsync(target, ["--version"], Path.GetDirectoryName(target)!, cancellationToken).ConfigureAwait(false);
        return $"{component.Name} updated: {FirstLine(version.StandardOutput)}";
    }

    private async Task<byte[]> DownloadAsync(Uri url, CancellationToken cancellationToken)
    {
        using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength > MaxDownloadBytes) throw new InvalidOperationException("The download is unexpectedly large.");
        var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        return bytes.Length > MaxDownloadBytes ? throw new InvalidOperationException("The download is unexpectedly large.") : bytes;
    }

    // ---- winget, pip, claude update ------------------------------------------------------------------------------

    private async Task<string> UpdateWithWingetAsync(Spec spec, ComponentState component, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        var winget = locateWinget() ?? throw new InvalidOperationException("winget was not found. Install \"App Installer\" from the Microsoft Store.");
        progress?.Report($"winget upgrade {spec.WingetId}…");
        var result = await RunAsync(winget, ["upgrade", "--id", spec.WingetId!, "--exact", "--silent", "--accept-package-agreements",
            "--accept-source-agreements", "--disable-interactivity"], Path.GetTempPath(), cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"winget could not update {component.Name} (exit code {result.ExitCode}): {LastLine(result.StandardOutput + result.StandardError)}");
        return $"{component.Name} updated with winget.";
    }

    private async Task<string> UpdateWithPipAsync(Spec spec, ComponentState component, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        var (python, prefix, user) = FindPythonFor(component.ExecutablePath!)
                                     ?? throw new InvalidOperationException("The Python that owns Semgrep was not found; run \"python -m pip install --upgrade semgrep\" yourself.");
        progress?.Report($"pip install --upgrade {spec.PyPiPackage}…");
        string[] args = [.. prefix, "-m", "pip", "install", .. (user ? new[] { "--user" } : []), "--upgrade", "--disable-pip-version-check", spec.PyPiPackage!];
        var result = await RunAsync(python, args, Path.GetTempPath(), cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"pip could not update {component.Name} (exit code {result.ExitCode}): {LastLine(result.StandardError.Length > 0 ? result.StandardError : result.StandardOutput)}");
        return $"{component.Name} updated with pip.";
    }

    private async Task<string> UpdateClaudeAsync(ComponentState component, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        progress?.Report("claude update…");
        var result = await RunAsync(component.ExecutablePath!, ["update"], Path.GetTempPath(), cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"claude update failed (exit code {result.ExitCode}): {LastLine(result.StandardOutput + result.StandardError)}");
        return "Claude Code: " + LastLine(result.StandardOutput);
    }

    /// <summary>
    /// The Python whose Scripts folder holds semgrep.exe: "…\Python313\Scripts" next to python.exe (machine install), or a
    /// per-user "%APPDATA%\Python\Python313\Scripts" whose interpreter lives under %LOCALAPPDATA%\Programs\Python or is
    /// reached through the py launcher (pip then needs --user).
    /// </summary>
    internal static (string Exe, string[] Prefix, bool User)? FindPythonFor(string semgrepPath)
    {
        var scripts = Path.GetDirectoryName(semgrepPath);
        var home = scripts is null ? null : Path.GetDirectoryName(scripts);
        if (home is null) return null;
        var inPlace = Path.Combine(home, "python.exe");
        if (File.Exists(inPlace)) return (inPlace, [], false);

        var version = Path.GetFileName(home);   // e.g. Python313
        var m = PythonFolder().Match(version);
        if (!m.Success) return null;
        foreach (var root in new[]
                 {
                     Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Python"),
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                 })
        {
            var candidate = Path.Combine(root, version, "python.exe");
            if (File.Exists(candidate)) return (candidate, [], true);
        }
        var py = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "py.exe");
        return File.Exists(py) ? (py, [$"-{m.Groups[1].Value}.{m.Groups[2].Value}"], true) : null;
    }

    // ---- Helpers -------------------------------------------------------------------------------------------------

    private ComponentSource DetectSource(InstalledComponent component, Spec? spec)
    {
        var path = component.ExecutablePath;
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return ComponentSource.Missing;
        if (component.Id == "claude-code") return ComponentSource.ClaudeUpdater;
        if (spec is { GitHubRepo: not null } && IsUnder(path, bundledToolsFolder)) return ComponentSource.Bundled;
        if (spec is { WingetId: not null } && path.Contains(@"\Microsoft\WinGet\", StringComparison.OrdinalIgnoreCase)) return ComponentSource.Winget;
        if (spec is { PyPiPackage: not null } && path.Contains(@"\Scripts\", StringComparison.OrdinalIgnoreCase) &&
            path.Contains(@"\Python", StringComparison.OrdinalIgnoreCase)) return ComponentSource.Pip;
        return ComponentSource.Manual;
    }

    private static bool IsUnder(string path, string folder) =>
        Path.GetFullPath(path).StartsWith(Path.GetFullPath(folder).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

    private async Task<JsonDocument> GitHubReleaseAsync(string repo, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://api.github.com/repos/{repo}/releases/latest");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        using var response = await http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
    }

    internal static bool IsReleaseDownload(Uri url, string repo) =>
        url.Scheme == Uri.UriSchemeHttps && url.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) &&
        url.AbsolutePath.StartsWith($"/{repo}/releases/download/", StringComparison.OrdinalIgnoreCase);

    private Task<ProcessRunResult> RunAsync(string exe, IReadOnlyList<string> args, string workingDirectory, CancellationToken cancellationToken) =>
        runner.RunAsync(new ProcessRunRequest(exe, args, workingDirectory, UpdateTimeout, 1024 * 1024), cancellationToken);

    private static string? Normalise(string? version) => AppVersion.Parse(version) is { } v ? $"{v.Major}.{v.Minor}.{v.Build}" : null;

    private static string FirstLine(string text) => text.Trim().Split('\n')[0].Trim();

    private static string LastLine(string text)
    {
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return lines.Length == 0 ? "(no output)" : lines[^1];
    }

    [GeneratedRegex(@"^gitleaks_[\d.]+_windows_x64\.zip$", RegexOptions.IgnoreCase)]
    private static partial Regex GitleaksAsset();

    [GeneratedRegex(@"^osv-scanner_windows_amd64\.exe$", RegexOptions.IgnoreCase)]
    private static partial Regex OsvAsset();

    [GeneratedRegex(@"^yara-x-v[\d.]+-x86_64-pc-windows-msvc\.zip$", RegexOptions.IgnoreCase)]
    private static partial Regex YaraAsset();

    [GeneratedRegex(@"^Python(\d)(\d+)$", RegexOptions.IgnoreCase)]
    private static partial Regex PythonFolder();
}
