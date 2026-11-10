using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using WebGuard.Core.Detection;
using WebGuard.Core.Updates;
using WebGuard.Intelligence;
using WebGuard.Presentation.ViewModels;

namespace WebGuard.Tests;

public static class ComponentUpdateTests
{
    [Test]
    public static async Task Check_detects_how_each_component_was_installed_and_which_are_outdated()
    {
        using var temp = new TempFolder();
        var tools = Path.Combine(temp.Path, "app", "tools");
        var gitleaks = temp.Write(@"app\tools\gitleaks.exe", "old");
        var osv = temp.Write(@"Microsoft\WinGet\Packages\Google.OSVScanner_x\osv-scanner.exe", "x");
        var semgrep = temp.Write(@"Python\Python313\Scripts\semgrep.exe", "x");
        var claude = temp.Write(@"local\bin\claude.exe", "x");
        var service = new ComponentUpdateService(new HttpClient(new Handler(Latest)), new FakeProcessRunner(_ => FakeProcessRunner.Ok("")), tools, () => null);

        var states = await service.CheckAsync(
        [
            new("gitleaks", "Gitleaks", "8.30.1", gitleaks),
            new("osv-scanner", "OSV-Scanner", "2.7.0", osv),
            new("semgrep", "Semgrep CE", "1.183.0", semgrep),
            new("yara-x", "YARA-X", null, null),
            new("claude-code", "Claude Code", "2.1.317", claude),
        ], CancellationToken.None);
        var byId = states.ToDictionary(s => s.Id);

        Assert.True(byId["gitleaks"] is { Source: ComponentSource.Bundled, LatestVersion: "8.31.0", UpdateAvailable: true, CanUpdate: true }, "bundled gitleaks outdated");
        Assert.True(byId["osv-scanner"] is { Source: ComponentSource.Winget, UpdateAvailable: false }, "winget osv-scanner current");
        Assert.True(byId["semgrep"] is { Source: ComponentSource.Pip, LatestVersion: "1.190.0", UpdateAvailable: true }, "pip semgrep outdated");
        Assert.True(byId["yara-x"] is { Source: ComponentSource.Missing, UpdateAvailable: false }, "missing yara-x is not offered an update");
        Assert.True(byId["claude-code"] is { Source: ComponentSource.ClaudeUpdater, LatestVersion: "2.1.318", UpdateAvailable: true }, "claude outdated");
    }

    [Test]
    public static async Task Bundled_tool_is_replaced_only_when_the_github_sha256_matches()
    {
        using var temp = new TempFolder();
        var tools = Path.Combine(temp.Path, "tools");
        var exe = temp.Write(@"tools\gitleaks.exe", "old exe");
        var zip = Zip("gitleaks.exe", "new exe");
        var goodDigest = "sha256:" + Convert.ToHexStringLower(SHA256.HashData(zip));
        var digest = goodDigest;
        var handler = new Handler(r => r.RequestUri!.Host == "api.github.com"
            ? Text("{\"tag_name\":\"v8.31.0\",\"assets\":[{\"name\":\"gitleaks_8.31.0_windows_x64.zip\",\"digest\":\"" + digest + "\"," +
                   "\"browser_download_url\":\"https://github.com/gitleaks/gitleaks/releases/download/v8.31.0/gitleaks_8.31.0_windows_x64.zip\"}]}")
            : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(zip) });
        var runner = new FakeProcessRunner(r => FakeProcessRunner.Ok("gitleaks version 8.31.0"));
        var service = new ComponentUpdateService(new HttpClient(handler), runner, tools, () => null);
        var state = new ComponentState("gitleaks", "Gitleaks", "8.30.1", "8.31.0", exe, ComponentSource.Bundled, true, null);

        digest = "sha256:" + new string('0', 64);
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.UpdateAsync(state, null, CancellationToken.None));
        Assert.Equal("old exe", File.ReadAllText(exe), "nothing changed when the hash does not match");

        digest = goodDigest;
        var result = await service.UpdateAsync(state, null, CancellationToken.None);
        Assert.Equal("new exe", File.ReadAllText(exe), "exe replaced from the zip");
        Assert.True(result.Contains("8.31.0", StringComparison.Ordinal), "result reports the new version");
        Assert.True(!File.Exists(exe + ".new") && !File.Exists(exe + ".old"), "no leftovers");
    }

    [Test]
    public static async Task Winget_pip_and_claude_updates_run_the_right_commands()
    {
        using var temp = new TempFolder();
        var winget = temp.Write("winget.exe", "x");
        var python = temp.Write(@"Python313\python.exe", "x");
        var semgrep = temp.Write(@"Python313\Scripts\semgrep.exe", "x");
        var claude = temp.Write("claude.exe", "x");
        var runner = new FakeProcessRunner(_ => FakeProcessRunner.Ok("Successfully updated"));
        var service = new ComponentUpdateService(new HttpClient(new Handler(Latest)), runner, Path.Combine(temp.Path, "tools"), () => winget);

        await service.UpdateAsync(new ComponentState("osv-scanner", "OSV-Scanner", "2.6.0", "2.7.0", temp.Write("osv.exe", "x"), ComponentSource.Winget, true, null),
            null, CancellationToken.None);
        Assert.True(runner.Requests[^1] is { ExecutablePath: var w, Arguments: ["upgrade", "--id", "Google.OSVScanner", ..] } && w == winget, "winget upgrade by id");

        await service.UpdateAsync(new ComponentState("semgrep", "Semgrep CE", "1.0.0", "1.190.0", semgrep, ComponentSource.Pip, true, null), null, CancellationToken.None);
        Assert.True(runner.Requests[^1].ExecutablePath == python && runner.Requests[^1].Arguments.SequenceEqual(
            ["-m", "pip", "install", "--upgrade", "--disable-pip-version-check", "semgrep"]), "pip with the python that owns semgrep");

        await service.UpdateAsync(new ComponentState("claude-code", "Claude Code", "2.1.317", "2.1.318", claude, ComponentSource.ClaudeUpdater, true, null),
            null, CancellationToken.None);
        Assert.True(runner.Requests[^1] is { Arguments: ["update"] } && runner.Requests[^1].ExecutablePath == claude, "claude update");
    }

    [Test]
    public static async Task Winget_updates_are_offered_only_when_the_winget_catalog_has_them()
    {
        using var temp = new TempFolder();
        var winget = temp.Write("winget.exe", "x");
        var osv = temp.Write(@"Microsoft\WinGet\Packages\Google.OSVScanner_x\osv-scanner.exe", "x");
        var catalog = "2.6.0";
        var runner = new FakeProcessRunner(r => r.Arguments[0] == "show"
            ? FakeProcessRunner.Ok($"Found OSV Scanner [Google.OSVScanner]\nVersion: {catalog}\nPublisher: Google\n")
            : FakeProcessRunner.Ok("No newer package versions are available from the configured sources.", unchecked((int)0x8A15002B)));
        var service = new ComponentUpdateService(new HttpClient(new Handler(Latest)), runner, Path.Combine(temp.Path, "tools"), () => winget);
        InstalledComponent[] installed = [new("osv-scanner", "OSV-Scanner", "2.6.0", osv)];

        var waiting = (await service.CheckAsync(installed, CancellationToken.None)).Single();
        Assert.True(waiting is { LatestVersion: "2.7.0", UpdateAvailable: false } && waiting.Note!.Contains("winget still offers 2.6.0", StringComparison.Ordinal),
            "released on GitHub but not in winget yet: no update button, explained");

        catalog = "2.7.0";
        Assert.True((await service.CheckAsync(installed, CancellationToken.None)).Single() is { UpdateAvailable: true, CanUpdate: true }, "offered once winget has it");

        var message = await service.UpdateAsync(new ComponentState("osv-scanner", "OSV-Scanner", "2.6.0", "2.7.0", osv, ComponentSource.Winget, true, null),
            null, CancellationToken.None);
        Assert.True(message.Contains("does not offer a newer", StringComparison.Ordinal), "winget 'no newer version' is reported, not thrown");
    }

    [Test]
    public static async Task Startup_check_offers_to_open_components_when_updates_exist()
    {
        var dialogs = new FakeDialogs();
        var updater = new StubUpdater();
        var components = new ComponentsViewModel([], new EngineCatalogViewModel([]), updater, null, dialogs);

        Assert.True(await components.CheckOnStartupAsync(), "confirmed popup opens Components");
        Assert.Equal(1, components.UpdatesAvailable, "one update listed");
        Assert.True(components.Rows.Single().UpdateCommand.CanExecute(null), "update button enabled");
        dialogs.ConfirmAnswer = false;
        Assert.True(!await components.CheckOnStartupAsync(), "Later keeps the current page");
    }

    // ---- Helpers ---------------------------------------------------------------------------------------------------

    private static HttpResponseMessage Latest(HttpRequestMessage r) => r.RequestUri!.AbsoluteUri switch
    {
        var u when u.Contains("gitleaks/gitleaks", StringComparison.Ordinal) => Text("""{"tag_name":"v8.31.0","assets":[]}"""),
        var u when u.Contains("osv-scanner", StringComparison.Ordinal) => Text("""{"tag_name":"v2.7.0","assets":[]}"""),
        var u when u.Contains("yara-x", StringComparison.Ordinal) => Text("""{"tag_name":"v1.22.1","assets":[]}"""),
        var u when u.Contains("pypi.org", StringComparison.Ordinal) => Text("""{"info":{"version":"1.190.0"}}"""),
        var u when u.Contains("registry.npmjs.org", StringComparison.Ordinal) => Text("""{"version":"2.1.318"}"""),
        _ => new HttpResponseMessage(HttpStatusCode.NotFound),
    };

    private static HttpResponseMessage Text(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8) };

    private static byte[] Zip(string name, string content)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            using var w = new StreamWriter(zip.CreateEntry("gitleaks_8.31.0/" + name).Open());
            w.Write(content);
        }
        return ms.ToArray();
    }

    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }

    private sealed class StubUpdater : IComponentUpdater
    {
        public Task<IReadOnlyList<ComponentState>> CheckAsync(IReadOnlyList<InstalledComponent> installed, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ComponentState>>(
                [new ComponentState("claude-code", "Claude Code", "2.1.317", "2.1.318", @"C:\x\claude.exe", ComponentSource.ClaudeUpdater, true, null)]);

        public Task<string> UpdateAsync(ComponentState component, IProgress<string>? progress, CancellationToken cancellationToken) => Task.FromResult("ok");
    }
}
