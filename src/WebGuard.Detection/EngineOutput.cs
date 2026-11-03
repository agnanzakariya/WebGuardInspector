using System.Text.Json;
using WebGuard.Core.Findings;

namespace WebGuard.Detection;

/// <summary>Helpers shared by the output parsers.</summary>
internal static class EngineOutput
{
    public const int MaxSnippetLength = 400;

    /// <summary>Maps a tool-reported path to a path relative to the scan root (OS separators, like the inventory).</summary>
    public static string ToRelative(string root, string? reported)
    {
        if (string.IsNullOrWhiteSpace(reported)) return string.Empty;
        var full = Path.GetFullPath(reported, root);
        return Path.GetRelativePath(root, full);
    }

    public static string? Snippet(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var trimmed = text.Trim();
        return trimmed.Length > MaxSnippetLength ? trimmed[..MaxSnippetLength] + "…" : trimmed;
    }

    public static Severity FromCvssScore(string? score) =>
        double.TryParse(score, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var value)
            ? value switch
            {
                >= 9.0 => Severity.Critical,
                >= 7.0 => Severity.High,
                >= 4.0 => Severity.Medium,
                > 0 => Severity.Low,
                _ => Severity.Info,
            }
            : Severity.Medium;

    public static Severity FromLabel(string? label, Severity fallback) => label?.Trim().ToUpperInvariant() switch
    {
        "CRITICAL" => Severity.Critical,
        "ERROR" or "HIGH" => Severity.High,
        "WARNING" or "MEDIUM" or "MODERATE" => Severity.Medium,
        "LOW" => Severity.Low,
        "INFO" or "INFORMATIONAL" or "NOTE" => Severity.Info,
        _ => fallback,
    };

    public static Confidence ConfidenceFromLabel(string? label, Confidence fallback) => label?.Trim().ToUpperInvariant() switch
    {
        "HIGH" => Confidence.High,
        "MEDIUM" => Confidence.Medium,
        "LOW" => Confidence.Low,
        _ => fallback,
    };

    public static string? GetString(this JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value)
            ? value.ValueKind switch
            {
                JsonValueKind.String => value.GetString(),
                JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => value.GetRawText(),
                _ => null,
            }
            : null;

    public static int GetInt(this JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.TryGetInt32(out var number) ? number : 0;

    public static JsonElement Child(this JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) ? value : default;

    public static IEnumerable<JsonElement> Items(this JsonElement element, string name)
    {
        var child = element.Child(name);
        return child.ValueKind == JsonValueKind.Array ? child.EnumerateArray() : [];
    }

    /// <summary>Reads a value that tools emit either as a string or an array of strings.</summary>
    public static IReadOnlyList<string> Strings(this JsonElement element, string name)
    {
        var child = element.Child(name);
        return child.ValueKind switch
        {
            JsonValueKind.String => [child.GetString()!],
            JsonValueKind.Array => child.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!).ToArray(),
            _ => [],
        };
    }

    /// <summary>"CWE-79: Improper Neutralization…" → "CWE-79".</summary>
    public static IReadOnlyList<string> NormalizeCwe(IEnumerable<string> values) => values
        .Select(v => v.Split(':', 2)[0].Trim())
        .Where(v => v.StartsWith("CWE-", StringComparison.OrdinalIgnoreCase))
        .Select(v => v.ToUpperInvariant())
        .Distinct(StringComparer.Ordinal)
        .ToArray();

    public static SecurityFinding Create(
        string engineId,
        string ruleId,
        string title,
        string description,
        FindingCategory category,
        Severity severity,
        Confidence confidence,
        SourceLocation location,
        string? fingerprintMaterial,
        IReadOnlyList<Evidence> evidence,
        IReadOnlyList<string> cweIds,
        IReadOnlyList<string> advisoryIds,
        string? remediation,
        DateTimeOffset detectedAtUtc) =>
        new(Guid.NewGuid(),
            FindingFingerprint.Compute(engineId, ruleId, location.RelativePath, fingerprintMaterial),
            engineId, ruleId, title, description, category, severity, confidence, FindingOrigin.Engine, location,
            evidence, cweIds, advisoryIds, remediation, ValidationStatus.New, detectedAtUtc);
}
