using WebGuard.Core.Scanning;

namespace WebGuard.Scanner;

/// <summary>Keeps the most recent sessions in memory only (tests, MCP). The desktop app uses <see cref="JsonScanHistoryStore"/>.</summary>
public sealed class InMemoryScanHistoryStore(int capacity = 50) : IScanHistoryStore
{
    private readonly LinkedList<ScanReport> _items = new();
    private readonly Dictionary<Guid, List<SessionActivity>> _activities = [];
    private readonly Lock _gate = new();

    public Task AddAsync(ScanReport report, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(report);
        lock (_gate)
        {
            _items.AddFirst(report);
            _activities.TryAdd(report.ScanId, []);
            while (_items.Count > capacity)
            {
                _activities.Remove(_items.Last!.Value.ScanId);
                _items.RemoveLast();
            }
        }
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<ScanReport>> GetRecentAsync(int take, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            return Task.FromResult<IReadOnlyList<ScanReport>>(_items.Take(Math.Max(0, take)).ToArray());
        }
    }

    public Task AppendActivityAsync(Guid scanId, SessionActivity activity, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(activity);
        lock (_gate)
        {
            if (_activities.TryGetValue(scanId, out var list)) list.Add(activity);
        }
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<SessionActivity>> GetActivitiesAsync(Guid scanId, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            return Task.FromResult<IReadOnlyList<SessionActivity>>(_activities.TryGetValue(scanId, out var list) ? list.ToArray() : []);
        }
    }
}
