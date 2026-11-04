using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using WebGuard.Core;
using WebGuard.Core.Updates;

namespace WebGuard.Intelligence;

/// <summary>
/// Checks the GitHub Releases of the app's repository for a newer version and downloads its installer. Only the
/// public release metadata is requested (no project data). The installer is downloaded only from the repository's
/// own release-download URLs and is accepted only when its SHA-256 matches the hash published with the release
/// (GitHub's asset digest, a "&lt;setup&gt;.sha256" asset, or a "SHA-256: …" line in the release notes).
/// </summary>
public sealed partial class GitHubUpdateService(HttpClient http, string owner, string repository, string downloadFolder,
    string? currentVersion = null, TimeProvider? timeProvider = null) : IUpdateService
{
    private const long MaxInstallerBytes = 500L * 1024 * 1024;
    private static readonly TimeSpan CheckTimeout = TimeSpan.FromSeconds(15);
    private readonly string _current = currentVersion ?? AppInfo.Version;
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    public static string DefaultDownloadFolder => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WebGuardInspector", "updates");

    public Uri ReleasesPage => new($"https://github.com/{owner}/{repository}/releases");

    public async Task<UpdateCheckResult> CheckAsync(CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(CheckTimeout);
        try
        {
            using var request = Api($"https://api.github.com/repos/{owner}/{repository}/releases/latest");
            using var response = await http.SendAsync(request, timeout.Token).ConfigureAwait(false);
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                return new UpdateCheckResult(_current, null, false, null, now);   // no release published yet
            if (!response.IsSuccessStatusCode)
                return new UpdateCheckResult(_current, null, false, $"GitHub answered {(int)response.StatusCode} {response.ReasonPhrase}.", now);

            var json = await response.Content.ReadAsStringAsync(timeout.Token).ConfigureAwait(false);
            var release = await ParseAsync(json, timeout.Token).ConfigureAwait(false);
            return new UpdateCheckResult(_current, release, release is not null && AppVersion.IsNewer(release.Version, _current), null, now);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException && !cancellationToken.IsCancellationRequested)
        {
            return new UpdateCheckResult(_current, null, false, ex is TaskCanceledException
                ? "GitHub did not answer in time."
                : "Could not reach GitHub: " + ex.Message, now);
        }
    }

    /// <summary>Reads the release JSON; the hash is looked up as described on the class.</summary>
    internal async Task<ReleaseInfo?> ParseAsync(string json, CancellationToken cancellationToken)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        string? Str(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

        var tag = Str(root, "tag_name");
        if (tag is null || AppVersion.Parse(tag) is null) return null;
        var notes = Str(root, "body") ?? string.Empty;
        var page = Uri.TryCreate(Str(root, "html_url"), UriKind.Absolute, out var html) ? html : ReleasesPage;
        DateTimeOffset? published = DateTimeOffset.TryParse(Str(root, "published_at"), System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal, out var p) ? p : null;

        JsonElement? setup = null;
        JsonElement? checksumAsset = null;
        if (root.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
        {
            foreach (var asset in assets.EnumerateArray())
            {
                var name = Str(asset, "name") ?? string.Empty;
                if (SetupName().IsMatch(name)) setup ??= asset;
            }
            if (setup is { } s)
            {
                var checksumName = Str(s, "name") + ".sha256";
                foreach (var asset in assets.EnumerateArray())
                {
                    if (string.Equals(Str(asset, "name"), checksumName, StringComparison.OrdinalIgnoreCase)) checksumAsset = asset;
                }
            }
        }

        Uri? setupUrl = null;
        string? setupName = null;
        long? size = null;
        string? sha = null;
        if (setup is { } a)
        {
            setupName = Str(a, "name");
            size = a.TryGetProperty("size", out var sz) && sz.TryGetInt64(out var n) ? n : null;
            setupUrl = Uri.TryCreate(Str(a, "browser_download_url"), UriKind.Absolute, out var u) && IsOwnDownload(u) ? u : null;
            sha = Sha256Of(Str(a, "digest"));
            if (sha is null && checksumAsset is { } c && Uri.TryCreate(Str(c, "browser_download_url"), UriKind.Absolute, out var cu) && IsOwnDownload(cu))
                sha = Sha256Of(await http.GetStringAsync(cu, cancellationToken).ConfigureAwait(false));
            sha ??= Sha256Of(NotesHash().Match(notes) is { Success: true } m ? m.Groups["hash"].Value : null);
        }

        var version = AppVersion.Parse(tag)!;
        return new ReleaseInfo($"{version.Major}.{version.Minor}.{version.Build}", tag, Str(root, "name") is { Length: > 0 } title ? title : tag,
            notes, page, published, setupUrl, setupName, size, sha);
    }

    public async Task<string> DownloadAsync(ReleaseInfo release, IProgress<double>? progress, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(release);
        if (release.SetupUrl is null || release.SetupFileName is null) throw new InvalidOperationException("This release has no installer for Windows.");
        if (release.Sha256 is null) throw new InvalidOperationException("No SHA-256 was published for this installer, so it is not installed automatically. Download it from the release page.");
        if (!IsOwnDownload(release.SetupUrl)) throw new InvalidOperationException("The installer URL is not a release download of this app's repository.");

        Directory.CreateDirectory(downloadFolder);
        var target = Path.Combine(downloadFolder, Path.GetFileName(release.SetupFileName));
        var partial = target + ".part";
        using (var response = await http.GetAsync(release.SetupUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false))
        {
            response.EnsureSuccessStatusCode();
            var total = response.Content.Headers.ContentLength ?? release.SetupSize;
            if (total > MaxInstallerBytes) throw new InvalidOperationException("The installer is unexpectedly large; download stopped.");
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            await using (source.ConfigureAwait(false))
            {
                var file = File.Create(partial);
                await using (file.ConfigureAwait(false))
                {
                    var buffer = new byte[81920];
                    long read = 0;
                    int n;
                    while ((n = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
                    {
                        read += n;
                        if (read > MaxInstallerBytes) throw new InvalidOperationException("The installer is unexpectedly large; download stopped.");
                        hash.AppendData(buffer, 0, n);
                        await file.WriteAsync(buffer.AsMemory(0, n), cancellationToken).ConfigureAwait(false);
                        if (total > 0) progress?.Report((double)read / total.Value);
                    }
                }
            }
            var actual = Convert.ToHexStringLower(hash.GetHashAndReset());
            if (!string.Equals(actual, release.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(partial);
                throw new InvalidOperationException($"The downloaded installer does not match the published SHA-256 (expected {release.Sha256}, got {actual}). It was deleted.");
            }
        }
        File.Move(partial, target, overwrite: true);
        progress?.Report(1);
        return target;
    }

    private static HttpRequestMessage Api(string url)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        request.Headers.Add("X-GitHub-Api-Version", "2022-11-28");
        return request;
    }

    /// <summary>Only https://github.com/&lt;owner&gt;/&lt;repo&gt;/releases/download/… (GitHub then redirects to its CDN).</summary>
    internal bool IsOwnDownload(Uri url) =>
        url.Scheme == Uri.UriSchemeHttps && url.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) &&
        url.AbsolutePath.StartsWith($"/{owner}/{repository}/releases/download/", StringComparison.OrdinalIgnoreCase);

    private static string? Sha256Of(string? text) =>
        text is not null && Hex64().Match(text) is { Success: true } m ? m.Value.ToLowerInvariant() : null;

    [GeneratedRegex(@"^Azura-WebGuard-Inspector-Setup-[0-9A-Za-z.\-]+\.exe$", RegexOptions.IgnoreCase)]
    private static partial Regex SetupName();

    [GeneratedRegex(@"\b[0-9a-fA-F]{64}\b")]
    private static partial Regex Hex64();

    [GeneratedRegex(@"SHA-?256[^0-9a-fA-F\r\n]{0,40}(?<hash>[0-9a-fA-F]{64})", RegexOptions.IgnoreCase)]
    private static partial Regex NotesHash();
}
