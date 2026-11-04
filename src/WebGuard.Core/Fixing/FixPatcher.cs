using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using WebGuard.Core.Findings;
using WebGuard.Core.Scanning;

namespace WebGuard.Core.Fixing;

/// <summary>
/// A project text file as the fixer works on it: UTF-8, line endings normalized to "\n". The original BOM and
/// line-ending style are remembered so a patched file is written back the way it was.
/// </summary>
public sealed record SourceFile(string RelativePath, string FullPath, string Text, bool HasBom, bool UsesCrlf, string Sha256)
{
    public const long MaxBytes = 1024 * 1024;

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>Reads a file strictly inside <paramref name="scope"/>. Binary, non-UTF-8 and oversized files are refused.</summary>
    public static bool TryRead(ProjectScope scope, string relativePath, out SourceFile file, out string error)
    {
        ArgumentNullException.ThrowIfNull(scope);
        file = null!;
        if (!scope.TryResolve(relativePath, out var path, out error)) return false;
        if (!File.Exists(path))
        {
            error = "The file no longer exists.";
            return false;
        }
        if (new FileInfo(path).Length > MaxBytes)
        {
            error = $"The file is larger than {MaxBytes / 1024} KB; fix it by hand.";
            return false;
        }

        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            error = "The file could not be read: " + ex.Message;
            return false;
        }
        if (Array.IndexOf(bytes, (byte)0, 0, Math.Min(bytes.Length, 8192)) >= 0)
        {
            error = "Binary file. It cannot be patched; delete or replace it with a clean copy.";
            return false;
        }

        var hasBom = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
        string text;
        try
        {
            text = StrictUtf8.GetString(bytes, hasBom ? 3 : 0, bytes.Length - (hasBom ? 3 : 0));
        }
        catch (DecoderFallbackException)
        {
            error = "The file is not UTF-8 text, so it is not patched automatically.";
            return false;
        }

        var usesCrlf = text.Contains("\r\n", StringComparison.Ordinal);
        file = new SourceFile(relativePath, path, text.Replace("\r\n", "\n", StringComparison.Ordinal), hasBom, usesCrlf, Hash(bytes));
        return true;
    }

    /// <summary>Bytes to write for <paramref name="text"/> ("\n" line endings) with this file's BOM and line endings.</summary>
    public byte[] Encode(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (UsesCrlf) text = text.Replace("\n", "\r\n", StringComparison.Ordinal);
        var body = StrictUtf8.GetBytes(text);
        return HasBom ? [0xEF, 0xBB, 0xBF, .. body] : body;
    }

    public static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
}

public enum DiffKind { Context, Removed, Added }

public sealed record DiffLine(DiffKind Kind, int? OldLine, int? NewLine, string Text);

public sealed record DiffHunk(int OldStart, int NewStart, IReadOnlyList<DiffLine> Lines);

/// <summary>Result of applying a proposal's edits to a file's text. Either every edit applied or none.</summary>
public sealed record PatchResult(string OriginalText, string PatchedText, IReadOnlyList<DiffHunk> Hunks, IReadOnlyList<string> Errors)
{
    public bool Succeeded => Errors.Count == 0;
    public int AddedLines => Hunks.Sum(h => h.Lines.Count(l => l.Kind == DiffKind.Added));
    public int RemovedLines => Hunks.Sum(h => h.Lines.Count(l => l.Kind == DiffKind.Removed));
}

/// <summary>
/// Applies AI-proposed edits as exact, unique text replacements. The model only ever saw the redacted file, so
/// <see cref="SourceRedactor.Mask"/> inside an edit's old text matches the hidden value on that line, and a mask
/// kept in the new text puts the same value back. Secrets are therefore never written as "[REDACTED]".
/// </summary>
public static class FixPatcher
{
    private const int ContextLines = 3;
    private const long MaxDiffCells = 4_000_000;
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromSeconds(2);

    public static PatchResult Apply(string text, IReadOnlyList<CodeEdit> edits)
    {
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(edits);
        var errors = new List<string>();
        if (edits.Count == 0) errors.Add("The proposal has no edits.");

        var current = text;
        for (var i = 0; i < edits.Count; i++)
        {
            if (TryApply(current, edits[i], out var next, out var error)) current = next;
            else errors.Add(string.Create(CultureInfo.InvariantCulture, $"Edit {i + 1}: {error}"));
        }
        if (errors.Count == 0 && current == text) errors.Add("The edits do not change the file.");
        return errors.Count == 0
            ? new PatchResult(text, current, Diff(text, current), [])
            : new PatchResult(text, text, [], errors);
    }

    private static bool TryApply(string text, CodeEdit edit, out string result, out string error)
    {
        result = text;
        var oldText = Normalize(edit.OldText);
        var newText = Normalize(edit.NewText);
        if (oldText.Length == 0)
        {
            error = "old_text is empty.";
            return false;
        }

        var parts = oldText.Split(SourceRedactor.Mask);
        var pattern = new StringBuilder();
        for (var i = 0; i < parts.Length; i++)
        {
            pattern.Append(Regex.Escape(parts[i]));
            // A hidden value inside the line ends where the copied text resumes; one at the end runs to the next delimiter.
            if (i < parts.Length - 1) pattern.Append(i == parts.Length - 2 && parts[^1].Length == 0 ? "([^\\s\"'`,;)]+)" : "([^\\n]+?)");
        }

        MatchCollection matches;
        try
        {
            matches = Regex.Matches(text, pattern.ToString(), RegexOptions.CultureInvariant, MatchTimeout);
            _ = matches.Count;
        }
        catch (RegexMatchTimeoutException)
        {
            error = "matching took too long.";
            return false;
        }
        if (matches.Count != 1)
        {
            error = matches.Count == 0
                ? "old_text was not found in the file (it may have changed since the proposal)."
                : $"old_text matches {matches.Count} places; it must be unique.";
            return false;
        }

        var match = matches[0];
        var hidden = match.Groups.Cast<Group>().Skip(1).Select(g => g.Value).ToArray();
        var newParts = newText.Split(SourceRedactor.Mask);
        if (newParts.Length - 1 > hidden.Length)
        {
            error = "new_text contains [REDACTED] that does not correspond to a hidden value in old_text.";
            return false;
        }
        var replacement = new StringBuilder(newParts[0]);
        for (var i = 1; i < newParts.Length; i++) replacement.Append(hidden[i - 1]).Append(newParts[i]);

        result = string.Concat(text.AsSpan(0, match.Index), replacement.ToString(), text.AsSpan(match.Index + match.Length));
        error = string.Empty;
        return true;
    }

    private static string Normalize(string? value) => (value ?? string.Empty).Replace("\r\n", "\n", StringComparison.Ordinal);

    /// <summary>Line diff grouped into hunks with three lines of context.</summary>
    public static IReadOnlyList<DiffHunk> Diff(string original, string patched)
    {
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(patched);
        var a = original.Split('\n');
        var b = patched.Split('\n');

        var prefix = 0;
        while (prefix < a.Length && prefix < b.Length && a[prefix] == b[prefix]) prefix++;
        var suffix = 0;
        while (suffix < a.Length - prefix && suffix < b.Length - prefix && a[^(suffix + 1)] == b[^(suffix + 1)]) suffix++;

        var ops = new List<DiffLine>();
        for (var i = 0; i < prefix; i++) ops.Add(new DiffLine(DiffKind.Context, i + 1, i + 1, a[i]));
        ops.AddRange(DiffMiddle(a, b, prefix, a.Length - suffix, b.Length - suffix));
        for (var k = suffix; k > 0; k--) ops.Add(new DiffLine(DiffKind.Context, a.Length - k + 1, b.Length - k + 1, a[^k]));
        return Group(ops);
    }

    /// <summary>Unified-diff style text of <paramref name="hunks"/> (for notes and copying).</summary>
    public static string ToUnifiedText(string relativePath, IReadOnlyList<DiffHunk> hunks)
    {
        ArgumentNullException.ThrowIfNull(hunks);
        var sb = new StringBuilder();
        sb.Append("--- a/").Append(relativePath).Append('\n').Append("+++ b/").Append(relativePath).Append('\n');
        foreach (var hunk in hunks)
        {
            sb.Append(CultureInfo.InvariantCulture, $"@@ -{hunk.OldStart} +{hunk.NewStart} @@\n");
            foreach (var line in hunk.Lines)
                sb.Append(line.Kind switch { DiffKind.Added => '+', DiffKind.Removed => '-', _ => ' ' }).Append(line.Text).Append('\n');
        }
        return sb.ToString();
    }

    /// <summary>LCS over the changed middle; a very large middle is shown as one removed block and one added block.</summary>
    private static List<DiffLine> DiffMiddle(string[] a, string[] b, int start, int endA, int endB)
    {
        var n = endA - start;
        var m = endB - start;
        var result = new List<DiffLine>();
        if ((long)n * m > MaxDiffCells)
        {
            for (var i = start; i < endA; i++) result.Add(new DiffLine(DiffKind.Removed, i + 1, null, a[i]));
            for (var j = start; j < endB; j++) result.Add(new DiffLine(DiffKind.Added, null, j + 1, b[j]));
            return result;
        }

        var lcs = new int[n + 1, m + 1];
        for (var i = n - 1; i >= 0; i--)
        {
            for (var j = m - 1; j >= 0; j--)
                lcs[i, j] = a[start + i] == b[start + j] ? lcs[i + 1, j + 1] + 1 : Math.Max(lcs[i + 1, j], lcs[i, j + 1]);
        }
        int x = 0, y = 0;
        while (x < n || y < m)
        {
            if (x < n && y < m && a[start + x] == b[start + y])
            {
                result.Add(new DiffLine(DiffKind.Context, start + x + 1, start + y + 1, a[start + x]));
                x++;
                y++;
            }
            // Removed lines go before added ones, as in a unified diff.
            else if (x < n && (y == m || lcs[x + 1, y] >= lcs[x, y + 1]))
            {
                result.Add(new DiffLine(DiffKind.Removed, start + x + 1, null, a[start + x]));
                x++;
            }
            else
            {
                result.Add(new DiffLine(DiffKind.Added, null, start + y + 1, b[start + y]));
                y++;
            }
        }
        return result;
    }

    private static List<DiffHunk> Group(List<DiffLine> ops)
    {
        var hunks = new List<DiffHunk>();
        var i = 0;
        while (i < ops.Count)
        {
            if (ops[i].Kind == DiffKind.Context)
            {
                i++;
                continue;
            }
            var from = Math.Max(0, i - ContextLines);
            var to = i;
            // Extend while the next change is within two context windows, so nearby edits share one hunk.
            while (to < ops.Count)
            {
                if (ops[to].Kind != DiffKind.Context)
                {
                    to++;
                    continue;
                }
                var next = to;
                while (next < ops.Count && ops[next].Kind == DiffKind.Context) next++;
                if (next < ops.Count && next - to <= ContextLines * 2) to = next;
                else break;
            }
            var end = Math.Min(ops.Count, to + ContextLines);
            var lines = ops.GetRange(from, end - from);
            hunks.Add(new DiffHunk(lines.FirstOrDefault(l => l.OldLine is not null)?.OldLine ?? 0,
                lines.FirstOrDefault(l => l.NewLine is not null)?.NewLine ?? 0, lines));
            i = end;
        }
        return hunks;
    }
}
