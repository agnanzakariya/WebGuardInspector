using WebGuard.Core.Detection;

namespace WebGuard.Detection;

public static class SecurityEngineCatalog
{
    /// <summary>The CLI engines, in the order they run during a scan.</summary>
    public static IReadOnlyList<ISecurityEngine> CreateDefault(
        IExternalProcessRunner runner,
        Func<string, ExternalToolOptions>? options = null,
        TimeProvider? timeProvider = null) =>
    [
        new SemgrepEngine(runner, options, timeProvider),
        new GitleaksEngine(runner, options, timeProvider),
        new OsvScannerEngine(runner, options, timeProvider),
        new YaraXEngine(runner, options, timeProvider),
        new ClamAvEngine(runner, options, timeProvider),
    ];
}
