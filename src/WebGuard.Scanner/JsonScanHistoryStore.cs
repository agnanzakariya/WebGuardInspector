using System.Text.Json;
using WebGuard.Core.Scanning;

namespace WebGuard.Scanner;

/// <summary>
/// Scan history kept across restarts: one JSON file per session under %LOCALAPPDATA%\WebGuardInspector\history with the
/// scan report (findings, engines, statistics; without the per-file inventory, which can hold tens of thousands of
/// entries) and the session's activities. The oldest sessions beyond <c>capacity</c> are deleted.
/// </summary>
public sealed class JsonScanHistoryStore(string directory, int capacity = 200) : IScanHistoryStore, IDisposable
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };
    private readonly SemaphoreSlim _gate = new(1, 1);
    private List<StoredSession>? _sessions;

    public static string DefaultDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WebGuardInspector", "history");

    public string Directory { get; } = directory;

    public void Dispose() => _gate.Dispose();

    /// <summary>A stored session: the report (inventory removed) and what was done with it.</summary>
    private sealed record StoredSession(ScanReport Report, List<SessionActivity> Activities);

    public async Task AddAsync(ScanReport report, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(report);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var sessions = Load();
            sessions.RemoveAll(s => s.Report.ScanId == report.ScanId);
            var session = new StoredSession(report with { Files = [] }, []);
            sessions.Insert(0, session);
            Write(session);
            foreach (var old in sessions.Skip(capacity).ToList())
            {
                sessions.Remove(old);
                TryDelete(PathFor(old.Report));
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<ScanReport>> GetRecentAsync(int take, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return Load().Take(Math.Max(0, take)).Select(s => s.Report).ToArray();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task AppendActivityAsync(Guid scanId, SessionActivity activity, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(activity);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Load().FirstOrDefault(s => s.Report.ScanId == scanId) is not { } session) return;
            session.Activities.Add(activity);
            Write(session);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<SessionActivity>> GetActivitiesAsync(Guid scanId, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return Load().FirstOrDefault(s => s.Report.ScanId == scanId)?.Activities.ToArray() ?? [];
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Reads every session file once; unreadable files are skipped (never fatal).</summary>
    private List<StoredSession> Load()
    {
        if (_sessions is not null) return _sessions;
        var sessions = new List<StoredSession>();
        if (System.IO.Directory.Exists(Directory))
        {
            foreach (var file in System.IO.Directory.EnumerateFiles(Directory, "session-*.json"))
            {
                try
                {
                    if (JsonSerializer.Deserialize<StoredSession>(File.ReadAllText(file), Json) is { Report: not null } s)
                        sessions.Add(s with { Activities = s.Activities ?? [] });
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or NotSupportedException)
                {
                    // A damaged file only hides that session.
                }
            }
        }
        _sessions = sessions.OrderByDescending(s => s.Report.StartedAtUtc).ToList();
        return _sessions;
    }

    private void Write(StoredSession session)
    {
        var path = PathFor(session.Report);
        var temp = path + ".tmp";
        try
        {
            System.IO.Directory.CreateDirectory(Directory);
            File.WriteAllText(temp, JsonSerializer.Serialize(session, Json));
            File.Move(temp, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // The session stays available in memory for this run.
            TryDelete(temp);
        }
    }

    private string PathFor(ScanReport report) => Path.Combine(Directory,
        $"session-{report.StartedAtUtc.UtcDateTime:yyyyMMdd-HHmmss}-{report.ScanId:N}.json");

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
