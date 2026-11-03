using WebGuard.Core.Detection;

namespace WebGuard.Intelligence;

/// <summary>User consent and credentials for external lookups, read on every call so Settings changes apply immediately.</summary>
/// <param name="AllowExternalLookups">Master opt-in. When false no request ever leaves the machine.</param>
/// <param name="AbuseChAuthKey">abuse.ch Auth-Key required by the MalwareBazaar and ThreatFox APIs.</param>
public sealed record IntelligenceSettings(bool AllowExternalLookups, string? AbuseChAuthKey)
{
    public static IntelligenceSettings Offline { get; } = new(false, null);

    internal const string ConsentMessage = "External lookups are off. Enable them in Settings → Privacy.";

    internal bool CanQueryAbuseCh => AllowExternalLookups && !string.IsNullOrWhiteSpace(AbuseChAuthKey);

    /// <summary>Status shared by the abuse.ch sources: consent first, then the Auth-Key.</summary>
    internal EngineStatus AbuseChStatus(string readyMessage) =>
        !AllowExternalLookups ? new EngineStatus(EngineAvailability.Disabled, null, null, ConsentMessage)
        : string.IsNullOrWhiteSpace(AbuseChAuthKey) ? new EngineStatus(EngineAvailability.NotInstalled, null, null,
            "Add a free abuse.ch Auth-Key in Settings → Privacy to enable hash lookups.")
        : new EngineStatus(EngineAvailability.Ready, null, null, readyMessage);
}
