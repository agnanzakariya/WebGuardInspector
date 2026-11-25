using WebGuard.AI;
using WebGuard.Core.AI;
using WebGuard.Core.Detection;
using WebGuard.Presentation.Services;

namespace WebGuard.Tests;

/// <summary>Starting LM Studio and loading the model when Azura opens.</summary>
public static class LocalAiLauncherTests
{
    private const string Listing = """
        Starting local model service...
        [{"type":"llm","modelKey":"qwen/qwen3.8-27b","path":"qwen/qwen3.8-27b"},{"type":"embedding","modelKey":"text-embedding-nomic-embed-text-v1.5"}]
        """;

    [Test]
    public static async Task Starts_the_server_and_loads_the_first_chat_model_with_the_chosen_gpu_share()
    {
        using var temp = new TempFolder();
        var lms = temp.Write("lms.exe", "x");
        var runner = new FakeProcessRunner(r => r.Arguments[0] switch
        {
            "server" => FakeProcessRunner.Ok("Success! Server is now running on port 1234"),
            "ps" => FakeProcessRunner.Ok("[]"),
            "ls" => FakeProcessRunner.Ok(Listing),
            _ => FakeProcessRunner.Ok("Model loaded successfully in 1m 11s."),
        });
        var launcher = new LmStudioLauncher(runner, () => lms);
        var messages = new List<string>();

        var result = await launcher.EnsureRunningAsync(new LocalAiStartup(null, "0.75", 8192), new SyncProgress(messages), CancellationToken.None);

        Assert.True(result is { Ready: true, Model: "qwen/qwen3.8-27b" } && result.Message.Contains("GPU offload 0.75", StringComparison.Ordinal), result.Message);
        var load = runner.Requests.Single(r => r.Arguments[0] == "load");
        Assert.True(load.Arguments.SequenceEqual(["load", "qwen/qwen3.8-27b", "-c", "8192", "-y", "--gpu", "0.75"]), "load arguments: " + string.Join(' ', load.Arguments));
        Assert.True(runner.Requests[0].Arguments.SequenceEqual(["server", "start"]) && messages.Any(m => m.StartsWith("Loading qwen", StringComparison.Ordinal)),
            "server first, progress shown");

        runner.Requests.Clear();
        await launcher.EnsureRunningAsync(new LocalAiStartup("my/model", LocalAiStartup.AutoGpu, 4096), null, CancellationToken.None);
        Assert.True(runner.Requests.Single(r => r.Arguments[0] == "load").Arguments.SequenceEqual(["load", "my/model", "-c", "4096", "-y"]),
            "the configured model; auto GPU leaves the choice to LM Studio");
    }

    [Test]
    public static async Task Does_nothing_more_when_a_chat_model_is_loaded_and_explains_problems()
    {
        using var temp = new TempFolder();
        var lms = temp.Write("lms.exe", "x");
        var loaded = new FakeProcessRunner(r => r.Arguments[0] == "ps"
            ? FakeProcessRunner.Ok("""[{"type":"llm","identifier":"qwen/qwen3.8-27b","modelKey":"qwen/qwen3.8-27b"}]""")
            : FakeProcessRunner.Ok("ok"));
        var ready = await new LmStudioLauncher(loaded, () => lms).EnsureRunningAsync(new LocalAiStartup(null, "auto", 8192), null, CancellationToken.None);
        Assert.True(ready is { Ready: true } && ready.Message.Contains("is loaded", StringComparison.Ordinal) && loaded.Requests.All(r => r.Arguments[0] != "load"),
            "an already loaded model is used as it is");

        var missing = await new LmStudioLauncher(loaded, () => null).EnsureRunningAsync(new LocalAiStartup(null, "auto", 8192), null, CancellationToken.None);
        Assert.True(!missing.Ready && missing.Message.Contains("lms", StringComparison.Ordinal), "no LM Studio CLI");

        var noModels = new FakeProcessRunner(r => r.Arguments[0] is "ps" or "ls" ? FakeProcessRunner.Ok("[]") : FakeProcessRunner.Ok("ok"));
        var none = await new LmStudioLauncher(noModels, () => lms).EnsureRunningAsync(new LocalAiStartup(null, "auto", 8192), null, CancellationToken.None);
        Assert.True(!none.Ready && none.Message.Contains("No chat model", StringComparison.Ordinal), "nothing downloaded");

        var tooBig = new FakeProcessRunner(r => r.Arguments[0] switch
        {
            "ps" => FakeProcessRunner.Ok("[]"),
            "ls" => FakeProcessRunner.Ok(Listing),
            "load" => FakeProcessRunner.Ok("\u001b[31m(X) CAUSE\u001b[0m\nFailed to initialize the context: failed to allocate buffer for kv cache", 1),
            _ => FakeProcessRunner.Ok("ok"),
        });
        var failed = await new LmStudioLauncher(tooBig, () => lms).EnsureRunningAsync(new LocalAiStartup(null, "max", 8192), null, CancellationToken.None);
        Assert.True(!failed.Ready && failed.Message.EndsWith("failed to allocate buffer for kv cache", StringComparison.Ordinal), "the tool's reason, without colour codes: " + failed.Message);
    }

    [Test]
    public static void Settings_accept_only_sensible_gpu_shares_and_lm_studio_endpoints()
    {
        Assert.True(ValidShares.All(LocalAiStartup.IsValidGpuOffload), "valid values");
        Assert.True(!InvalidShares.Any(LocalAiStartup.IsValidGpuOffload), "invalid values");
        Assert.True(new AppSettings().UsesLmStudio && !(new AppSettings { AiEndpoint = "http://127.0.0.1:11434/v1" }).UsesLmStudio,
            "LM Studio's port only; Ollama is left alone");
    }

    private static readonly string[] ValidShares = ["auto", "off", "MAX", "0", "0.75", "1"];
    private static readonly string[] InvalidShares = ["", "1.5", "-0.1", "half"];

    private sealed class SyncProgress(List<string> messages) : IProgress<string>
    {
        public void Report(string value) => messages.Add(value);
    }
}
