using WebGuard.Core.Scanning;

namespace WebGuard.Scanner;

/// <summary>Keeps the most recent scans for the current session. Replaced by PostgreSQL in Phase 4.</summary>
public sealed class InMemoryScanHistoryStore(int capacity = 50) : IScanHistoryStore
{
    private readonly LinkedList<ScanReport> _items = new();
    private readonly Lock _gate = new();

    public Task AddAsync(ScanReport report, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(report);
        lock (_gate)
        {
            _items.AddFirst(report);
            while (_items.Count > capacity) _items.RemoveLast();
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
}
