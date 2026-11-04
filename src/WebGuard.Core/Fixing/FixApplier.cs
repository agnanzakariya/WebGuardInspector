using System.Globalization;
using System.Text.Json;
using WebGuard.Core.Scanning;

namespace WebGuard.Core.Fixing;

/// <summary>A patch written to a project file, with the backup needed to undo it.</summary>
public sealed record AppliedFix(string RelativePath, string FullPath, string BackupPath, string OriginalSha256, string PatchedSha256, DateTimeOffset AppliedAtUtc);

/// <summary>
/// Writes reviewed patches to project files. The original is copied to a backup folder outside the project first
/// (so the next scan does not pick it up), the edits are re-applied to the file as it is now, and the new content
/// replaces the file atomically. Undo restores the backup only if nobody changed the file since.
/// </summary>
public sealed class FixApplier(string backupRoot, TimeProvider? timeProvider = null)
{
    private static readonly JsonSerializerOptions ManifestOptions = new() { WriteIndented = true };
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;

    public static string DefaultBackupRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WebGuardInspector", "fix-backups");

    public string BackupRoot { get; } = backupRoot;

    /// <summary>Reads the file, applies <paramref name="edits"/> and writes it. Throws when the edits no longer apply.</summary>
    public (AppliedFix Fix, PatchResult Patch) Apply(ProjectScope scope, string relativePath, IReadOnlyList<CodeEdit> edits)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(edits);
        if (!SourceFile.TryRead(scope, relativePath, out var file, out var error)) throw new InvalidOperationException(error);
        var patch = FixPatcher.Apply(file.Text, edits);
        if (!patch.Succeeded) throw new InvalidOperationException("The fix no longer applies: " + string.Join(" ", patch.Errors));

        var now = _time.GetUtcNow();
        var folder = Path.Combine(BackupRoot, now.ToString("yyyyMMdd-HHmmss-fff", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N")[..6]);
        var backup = Path.Combine(folder, "files", relativePath.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(backup)!);
        File.Copy(file.FullPath, backup);

        var bytes = file.Encode(patch.PatchedText);
        var fix = new AppliedFix(relativePath, file.FullPath, backup, file.Sha256, SourceFile.Hash(bytes), now);
        File.WriteAllText(Path.Combine(folder, "manifest.json"), JsonSerializer.Serialize(new
        {
            project = scope.Root,
            file = relativePath,
            original_sha256 = fix.OriginalSha256,
            patched_sha256 = fix.PatchedSha256,
            applied_at_utc = now,
        }, ManifestOptions));

        WriteAtomically(file.FullPath, bytes);
        return (fix, patch);
    }

    /// <summary>Puts the original back. Refused when the file changed after the fix (e.g. a later fix to the same file).</summary>
    public static void Undo(AppliedFix fix)
    {
        ArgumentNullException.ThrowIfNull(fix);
        if (!File.Exists(fix.BackupPath)) throw new InvalidOperationException("The backup is missing: " + fix.BackupPath);
        if (File.Exists(fix.FullPath) && SourceFile.Hash(File.ReadAllBytes(fix.FullPath)) != fix.PatchedSha256)
            throw new InvalidOperationException("The file changed after this fix was applied. Undo the later fix first, or restore the backup by hand: " + fix.BackupPath);
        WriteAtomically(fix.FullPath, File.ReadAllBytes(fix.BackupPath));
    }

    private static void WriteAtomically(string path, byte[] bytes)
    {
        var temp = path + ".webguard-tmp";
        File.WriteAllBytes(temp, bytes);
        File.Move(temp, path, overwrite: true);
    }
}
