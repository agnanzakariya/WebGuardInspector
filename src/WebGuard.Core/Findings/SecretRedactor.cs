namespace WebGuard.Core.Findings;

/// <summary>Masks secret values before they are displayed, logged, exported or sent to AI.</summary>
public static class SecretRedactor
{
    public static string Redact(string? secret, int visiblePrefix = 4)
    {
        if (string.IsNullOrEmpty(secret)) return string.Empty;
        if (secret.Length <= visiblePrefix + 4) return new string('*', secret.Length);
        return string.Concat(secret.AsSpan(0, visiblePrefix), new string('*', Math.Min(secret.Length - visiblePrefix, 16)));
    }
}
