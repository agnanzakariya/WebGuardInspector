using WebGuard.Core.Detection;
using WebGuard.Core.Findings;

namespace WebGuard.Detection;

/// <summary>
/// Placeholder that satisfies <see cref="ISecurityEngine"/> until a real adapter lands (e.g. Roslyn analyzers in Phase 3).
/// It reports <see cref="EngineAvailability.Planned"/> and never launches a process.
/// </summary>
public abstract class PlannedSecurityEngine : ISecurityEngine
{
    public abstract SecurityEngineInfo Info { get; }

    public Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken) =>
        Task.FromResult(EngineStatus.Planned(Info.PlannedPhase));

    public Task<EngineScanResult> ScanAsync(EngineScanRequest request, IProgress<EngineProgress>? progress, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return Task.FromResult(new EngineScanResult(Info.Id, false, Array.Empty<SecurityFinding>(), TimeSpan.Zero, null,
            $"{Info.DisplayName} is not implemented yet ({Info.PlannedPhase})."));
    }
}
