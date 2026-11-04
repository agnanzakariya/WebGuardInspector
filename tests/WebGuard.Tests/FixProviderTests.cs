using System.Net;
using System.Text;
using WebGuard.AI;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Fixing;
using WebGuard.Core.Scanning;
using WebGuard.Presentation.Services;
using WebGuard.Presentation.ViewModels;

namespace WebGuard.Tests;

/// <summary>Choosing Claude or the local model for fixing.</summary>
public static class FixProviderTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 4, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public static async Task Local_model_fixer_sends_the_fix_prompt_to_the_loopback_server_and_parses_the_json_answer()
    {
        string? sentBody = null;
        var http = new HttpClient(new Handler(r =>
        {
            if (r.RequestUri!.AbsolutePath.EndsWith("/models", StringComparison.Ordinal))
                return Json("""{"data":[{"id":"text-embedding-nomic"},{"id":"qwen/qwen3.5-9b"}]}""");
            sentBody = r.Content!.ReadAsStringAsync().Result;
            return Json("""{"choices":[{"message":{"content":"<think>x</think>```json\n{\"verdict\":\"fix\",\"explanation\":\"Use a prepared statement.\",\"confidence\":\"medium\",\"edits\":[{\"old_text\":\"a();\",\"new_text\":\"b();\"}],\"follow_up_command\":\"\"}\n```"}}]}""");
        }));
        var fixer = new LocalModelCodeFixer(new OpenAiCompatibleClient(http), () => new AiSettings(true, "http://127.0.0.1:1234/v1", null), () => true,
            new FixedTimeProvider(Now));

        var status = await fixer.GetStatusAsync(CancellationToken.None);
        Assert.True(status.Availability == EngineAvailability.Ready && status.Message!.Contains("qwen/qwen3.5-9b", StringComparison.Ordinal), "first chat model used");
        Assert.Equal(FixLimits.LocalModel, fixer.Limits, "smaller limits for local models");

        var proposal = await fixer.ProposeAsync(new FixRequest(Finding("a.php", 1), "a();\n", []), CancellationToken.None);
        Assert.True(proposal is { Verdict: FixVerdict.Fix, Model: "qwen/qwen3.5-9b", Confidence: Confidence.Medium, FollowUpCommand: null }, "answer parsed");
        Assert.Equal(new CodeEdit("a();", "b();"), proposal.Edits.Single(), "edit parsed out of a fenced, think-prefixed reply");
        Assert.True(sentBody!.Contains("FILE CONTENT of a.php", StringComparison.Ordinal) && sentBody.Contains("Reply with ONLY one JSON object", StringComparison.Ordinal),
            "same fix prompt plus an explicit JSON instruction");

        var remote = new LocalModelCodeFixer(new OpenAiCompatibleClient(http), () => new AiSettings(true, "https://api.example.com/v1", null), () => true);
        Assert.Equal(EngineAvailability.Error, (await remote.GetStatusAsync(CancellationToken.None)).Availability, "only loopback endpoints");
        Assert.True(Throws(() => LocalModelCodeFixer.ParseReply(Guid.Empty, "m", "Sorry, I cannot help.", Now)), "non-JSON answers are reported");
    }

    [Test]
    public static void Requests_follow_the_limits_of_the_chosen_fixer()
    {
        using var temp = new TempFolder();
        var text = new StringBuilder();
        for (var i = 1; i <= 1000; i++) text.Append("$value").Append(i).Append(" = ").Append(i).Append(";\n");   // ~20k chars
        temp.Write("mid.php", text.ToString());
        var scope = new ProjectScope(temp.Path);
        var finding = Finding("mid.php", 500);

        Assert.True(FixRequestBuilder.TryBuild(scope, finding, [finding], out var forClaude, out _, FixLimits.Claude), "claude request");
        Assert.True(forClaude.Excerpt is null, "Claude gets the whole 20k-character file");
        Assert.True(FixRequestBuilder.TryBuild(scope, finding, [finding], out var forLocal, out _, FixLimits.LocalModel), "local request");
        Assert.True(forLocal.Excerpt is { FirstLine: 460, LastLine: 540 } && forLocal.RedactedFileContent.Length <= FixLimits.LocalModel.MaxExcerptChars,
            "the local model gets an excerpt of 40 lines around the finding (fits an 8k context)");
    }

    [Test]
    public static async Task Selectable_fixer_follows_the_setting_and_settings_page_saves_it()
    {
        var settings = new SettingsService(new MemorySettingsStore());
        var claude = new NamedFixer("Claude", FixLimits.Claude);
        var local = new NamedFixer("the local model", FixLimits.LocalModel);
        var fixer = new SelectableCodeFixer(() => settings.Current.FixProvider == FixProvider.LocalModel, claude, local);
        Assert.Equal("Claude", fixer.ShortName, "Claude by default");

        var page = new SettingsViewModel(settings, new FakeTheme(), new EngineCatalogViewModel([]));
        Assert.True(page.UsesClaudeForFixing && !page.UsesLocalModelForFixing, "page shows Claude");
        page.FixProviderChoice = SettingsViewModel.LocalProviderChoice;
        page.SaveCommand.Execute(null);
        Assert.Equal(FixProvider.LocalModel, settings.Current.FixProvider, "saved");
        Assert.True(fixer.ShortName == "the local model" && fixer.Limits == FixLimits.LocalModel, "switch takes effect without a restart");
        await fixer.ProposeAsync(new FixRequest(Finding("a.php", 1), "x", []), CancellationToken.None);
        Assert.True(local.Calls == 1 && claude.Calls == 0, "requests go to the chosen fixer");

        var wizard = new SetupWizardViewModel(settings, new FakeTheme(), new EngineCatalogViewModel([]));
        Assert.True(wizard.FixChoices.SequenceEqual([SetupWizardViewModel.FixWithClaude, SetupWizardViewModel.FixWithLocalModel, SetupWizardViewModel.DontUse]),
            "wizard offers both providers");
    }

    // ---- Helpers ---------------------------------------------------------------------------------------------------

    private static bool Throws(Action action)
    {
        try
        {
            action();
            return false;
        }
        catch (InvalidOperationException)
        {
            return true;
        }
    }

    private static SecurityFinding Finding(string path, int line) => new(
        Guid.NewGuid(), FindingFingerprint.Compute("semgrep", "r", path, "t" + line), "semgrep", "r", "Issue", "d", FindingCategory.Vulnerability,
        Severity.High, Confidence.Medium, FindingOrigin.Engine, new SourceLocation(path, line, line), [], [], [], null, ValidationStatus.New, Now);

    private static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(respond(request));
    }

    private sealed class NamedFixer(string shortName, FixLimits limits) : ICodeFixer
    {
        public int Calls { get; private set; }
        public string DisplayName => shortName;
        public string ShortName => shortName;
        public FixLimits Limits => limits;
        public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) => Task.FromResult(new EngineStatus(EngineAvailability.Ready, "1", null, "ok"));

        public Task<FixProposal> ProposeAsync(FixRequest request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new FixProposal(request.Finding.Id, shortName, FixVerdict.CannotFix, "n/a", [], Confidence.Low, Now));
        }
    }
}
