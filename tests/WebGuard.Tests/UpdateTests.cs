using System.Net;
using System.Security.Cryptography;
using System.Text;
using WebGuard.Core.Updates;
using WebGuard.Intelligence;
using WebGuard.Presentation.Services;
using WebGuard.Presentation.ViewModels;

namespace WebGuard.Tests;

public static class UpdateTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 4, 12, 0, 0, TimeSpan.Zero);
    private const string Installer = "fake installer bytes";
    private static readonly string InstallerSha = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Installer)));
    private const string DownloadUrl = "https://github.com/acme/app/releases/download/v0.8.0/Azura-WebGuard-Inspector-Setup-0.8.0.exe";

    [Test]
    public static void Versions_compare_numerically_and_ignore_prefixes()
    {
        Assert.True(AppVersion.IsNewer("v0.10.0", "0.9.5"), "0.10 is newer than 0.9.5");
        Assert.True(!AppVersion.IsNewer("v0.7.0", "0.7.0"), "same version is not newer");
        Assert.True(!AppVersion.IsNewer("0.7", "0.7.0"), "0.7 equals 0.7.0");
        Assert.True(AppVersion.IsNewer("1.0.0-beta", "0.9.0"), "pre-release suffix ignored");
        Assert.True(!AppVersion.IsNewer("latest", "0.1.0"), "non-version tags are ignored");
    }

    [Test]
    public static async Task Check_reads_the_latest_release_with_its_asset_digest()
    {
        using var temp = new TempFolder();
        var service = Service(temp.Path, _ => (HttpStatusCode.OK, Release("v0.8.0", DownloadUrl, digest: "sha256:" + InstallerSha)));
        var result = await service.CheckAsync(CancellationToken.None);

        Assert.True(result.IsNewer && result.Error is null, "0.8.0 is newer than 0.7.0");
        var latest = result.Latest!;
        Assert.Equal("0.8.0", latest.Version, "version");
        Assert.Equal(InstallerSha, latest.Sha256, "digest used as the checksum");
        Assert.Equal(DownloadUrl, latest.SetupUrl!.AbsoluteUri, "installer asset found");
        Assert.Equal("Azura 0.8.0", latest.Name, "release name");
    }

    [Test]
    public static async Task Check_handles_no_release_old_release_foreign_urls_and_notes_hashes()
    {
        using var temp = new TempFolder();
        var none = await Service(temp.Path, _ => (HttpStatusCode.NotFound, "{}")).CheckAsync(CancellationToken.None);
        Assert.True(none.Latest is null && !none.IsNewer && none.Error is null, "no release yet is not an error");

        var old = await Service(temp.Path, _ => (HttpStatusCode.OK, Release("v0.6.0", DownloadUrl))).CheckAsync(CancellationToken.None);
        Assert.True(!old.IsNewer, "older release is not offered");

        var foreign = await Service(temp.Path, _ => (HttpStatusCode.OK,
            Release("v0.8.0", "https://evil.example/Azura-WebGuard-Inspector-Setup-0.8.0.exe", digest: "sha256:" + InstallerSha))).CheckAsync(CancellationToken.None);
        Assert.True(foreign.IsNewer && foreign.Latest!.SetupUrl is null, "installer outside the repository's release downloads is ignored");

        var notes = await Service(temp.Path, _ => (HttpStatusCode.OK, Release("v0.8.0", DownloadUrl, body: "Fixes.\n\nSHA-256: " + InstallerSha.ToUpperInvariant())))
            .CheckAsync(CancellationToken.None);
        Assert.Equal(InstallerSha, notes.Latest!.Sha256, "checksum taken from the release notes");

        var error = await Service(temp.Path, _ => (HttpStatusCode.Forbidden, "{}")).CheckAsync(CancellationToken.None);
        Assert.True(error.Error!.Contains("403", StringComparison.Ordinal), "API errors are reported, not thrown");
    }

    [Test]
    public static async Task Download_keeps_the_installer_only_when_the_sha256_matches()
    {
        using var temp = new TempFolder();
        var service = Service(temp.Path, r => r.RequestUri!.AbsoluteUri == DownloadUrl ? (HttpStatusCode.OK, Installer) : (HttpStatusCode.NotFound, "{}"));
        var release = new ReleaseInfo("0.8.0", "v0.8.0", "Azura 0.8.0", "", new Uri("https://github.com/acme/app/releases/tag/v0.8.0"), Now,
            new Uri(DownloadUrl), "Azura-WebGuard-Inspector-Setup-0.8.0.exe", Installer.Length, InstallerSha);

        var path = await service.DownloadAsync(release, null, CancellationToken.None);
        Assert.Equal(Installer, File.ReadAllText(path), "installer saved");

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.DownloadAsync(release with { Sha256 = new string('0', 64) }, null, CancellationToken.None));
        Assert.True(!Directory.EnumerateFiles(temp.Path, "*.part").Any(), "a mismatching download is deleted");
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.DownloadAsync(release with { Sha256 = null }, null, CancellationToken.None));
    }

    [Test]
    public static async Task About_checks_once_a_day_when_allowed_and_installs_after_confirmation()
    {
        using var temp = new TempFolder();
        var calls = 0;
        var service = Service(temp.Path, r =>
        {
            if (r.RequestUri!.AbsoluteUri == DownloadUrl) return (HttpStatusCode.OK, Installer);
            calls++;
            return (HttpStatusCode.OK, Release("v0.8.0", DownloadUrl, digest: "sha256:" + InstallerSha));
        });
        var settings = new SettingsService(new MemorySettingsStore());
        var time = new FixedTimeProvider(Now);
        var dialogs = new FakeDialogs();
        var installer = new FakeInstaller();
        var paths = new AboutPaths(temp.Path, "s", "l", "b", temp.Path, "c", Path.Combine(temp.Path, "WebGuard.Mcp.exe"), temp.Path);
        var about = new AboutViewModel(settings, new EngineCatalogViewModel([]), paths, service, dialogs: dialogs, installer: installer, timeProvider: time);

        settings.Update(s => s with { CheckForUpdates = false });
        await about.CheckOnStartupAsync();
        Assert.Equal(0, calls, "no start-up check when switched off");

        about.AutoCheck = true;
        await about.CheckOnStartupAsync();
        Assert.Equal(1, calls, "checked once");
        Assert.True(about.IsUpdateAvailable && about.UpdateBadge == "Update 0.8.0 available", "update offered");
        await about.CheckOnStartupAsync();
        Assert.Equal(1, calls, "not again within a day");
        time.Now = Now.AddDays(1);
        await about.CheckOnStartupAsync();
        Assert.Equal(2, calls, "again the next day");

        dialogs.ConfirmAnswer = false;
        await about.InstallUpdateCommand.ExecuteAsync();
        Assert.Equal(null, installer.Started, "nothing runs without confirmation");
        dialogs.ConfirmAnswer = true;
        await about.InstallUpdateCommand.ExecuteAsync();
        Assert.True(installer.Started is not null && File.ReadAllText(installer.Started) == Installer, "verified installer started");
    }

    // ---- Helpers ---------------------------------------------------------------------------------------------------

    private static GitHubUpdateService Service(string folder, Func<HttpRequestMessage, (HttpStatusCode, string)> respond) =>
        new(new HttpClient(new StatusHandler(respond)), "acme", "app", folder, "0.7.0", new FixedTimeProvider(Now));

    private static string Release(string tag, string url, string? digest = null, string body = "Notes.") =>
        System.Text.Json.JsonSerializer.Serialize(new
        {
            tag_name = tag,
            name = "Azura " + tag.TrimStart('v'),
            body,
            html_url = "https://github.com/acme/app/releases/tag/" + tag,
            published_at = "2026-11-03T10:00:00Z",
            assets = new object[]
            {
                new { name = "Azura-WebGuard-Inspector-Setup-" + tag.TrimStart('v') + ".exe", browser_download_url = url, size = Installer.Length, digest },
                new { name = "README.txt", browser_download_url = "https://github.com/acme/app/releases/download/" + tag + "/README.txt", size = 3, digest = (string?)null },
            },
        });

    private sealed class StatusHandler(Func<HttpRequestMessage, (HttpStatusCode Status, string Body)> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var (status, body) = respond(request);
            return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8) });
        }
    }

    private sealed class FakeInstaller : IInstallerLauncher
    {
        public string? Started { get; private set; }
        public void RunAndExit(string installerPath) => Started = installerPath;
    }
}
