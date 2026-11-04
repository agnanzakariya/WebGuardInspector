using System.Text.Json.Serialization;
using WebGuard.Core.Detection;
using WebGuard.Core.Findings;
using WebGuard.Core.Scanning;

namespace WebGuard.Core.Fixing;

/// <summary>What the AI concluded about a finding it was asked to fix.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<FixVerdict>))]
public enum FixVerdict { Fix, FalsePositive, CannotFix }

/// <summary>
/// One exact text replacement. <see cref="OldText"/> is copied from the redacted file the model saw, so it may
/// contain <see cref="SourceRedactor.Mask"/> where a secret was; <see cref="FixPatcher"/> matches those parts as wildcards.
/// </summary>
public sealed record CodeEdit(string OldText, string NewText);

/// <summary>Everything the fixer sees: the finding and the whole file, already redacted. Never the original secrets.</summary>
public sealed record FixRequest(
    SecurityFinding Finding,
    string RedactedFileContent,
    IReadOnlyList<SecurityFinding> OtherFindingsInFile);

public static class FixRequestBuilder
{
    /// <summary>Upper bound on the redacted file text sent to the model.</summary>
    public const int MaxContentChars = 200_000;

    /// <summary>
    /// Reads the finding's file inside <paramref name="scope"/> and redacts it. Fails for files the fixer cannot
    /// patch (binary, not UTF-8, too large), so they are reported without asking the model.
    /// </summary>
    public static bool TryBuild(ProjectScope scope, SecurityFinding finding, IEnumerable<SecurityFinding> allFindings,
        out FixRequest request, out string error)
    {
        ArgumentNullException.ThrowIfNull(finding);
        ArgumentNullException.ThrowIfNull(allFindings);
        request = null!;
        if (!SourceFile.TryRead(scope, finding.Location.RelativePath, out var file, out error)) return false;
        var redacted = SourceRedactor.Redact(file.Text, file.FullPath);
        if (redacted.Length > MaxContentChars)
        {
            error = $"The file has {redacted.Length:N0} characters; the limit for an AI fix is {MaxContentChars:N0}.";
            return false;
        }
        var others = allFindings
            .Where(f => f.Id != finding.Id && string.Equals(f.Location.RelativePath, finding.Location.RelativePath, StringComparison.OrdinalIgnoreCase))
            .Take(20)
            .ToArray();
        request = new FixRequest(finding, redacted, others);
        return true;
    }
}

/// <summary>AI output: a hypothesis with proposed edits. Nothing is written until a person applies it.</summary>
public sealed record FixProposal(
    Guid FindingId,
    string Model,
    FixVerdict Verdict,
    string Explanation,
    IReadOnlyList<CodeEdit> Edits,
    Confidence Confidence,
    DateTimeOffset CreatedAtUtc);

public interface ICodeFixer
{
    string DisplayName { get; }
    Task<EngineStatus> GetStatusAsync(CancellationToken cancellationToken);
    Task<FixProposal> ProposeAsync(FixRequest request, CancellationToken cancellationToken);
}
