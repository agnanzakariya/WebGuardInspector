namespace WebGuard.Intelligence;

/// <summary>User consent and credentials for external lookups, read on every call so Settings changes apply immediately.</summary>
/// <param name="AllowExternalLookups">Master opt-in. When false no request ever leaves the machine.</param>
/// <param name="AbuseChAuthKey">abuse.ch Auth-Key required by the MalwareBazaar API.</param>
public sealed record IntelligenceSettings(bool AllowExternalLookups, string? AbuseChAuthKey)
{
    public static IntelligenceSettings Offline { get; } = new(false, null);

    internal const string ConsentMessage = "External lookups are off. Enable them in Settings → Privacy.";
}
