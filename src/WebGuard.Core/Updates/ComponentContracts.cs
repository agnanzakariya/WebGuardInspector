namespace WebGuard.Core.Updates;

/// <summary>How a component on this PC was installed, which decides how it is updated.</summary>
public enum ComponentSource
{
    /// <summary>Shipped in the app's tools folder: replaced with the official GitHub release asset (SHA-256 checked).</summary>
    Bundled,
    /// <summary>Installed with winget: "winget upgrade".</summary>
    Winget,
    /// <summary>Installed with pip: "python -m pip install --user --upgrade".</summary>
    Pip,
    /// <summary>Claude Code's native installer: "claude update".</summary>
    ClaudeUpdater,
    /// <summary>Signature database updated by Azura (ClamAV freshclam).</summary>
    SignatureUpdater,
    /// <summary>Installed some other way; updated by hand.</summary>
    Manual,
    /// <summary>Not installed.</summary>
    Missing,
}

/// <summary>A component as found on this PC (version and the executable Azura actually uses).</summary>
public sealed record InstalledComponent(string Id, string Name, string? Version, string? ExecutablePath);

/// <summary>Installed and latest version of one component and how it would be updated.</summary>
public sealed record ComponentState(
    string Id,
    string Name,
    string? InstalledVersion,
    string? LatestVersion,
    string? ExecutablePath,
    ComponentSource Source,
    bool UpdateAvailable,
    string? Note)
{
    /// <summary>Update can be done from the app (not for manual installs or when the latest version is unknown).</summary>
    public bool CanUpdate => UpdateAvailable && Source is ComponentSource.Bundled or ComponentSource.Winget or ComponentSource.Pip
        or ComponentSource.ClaudeUpdater or ComponentSource.SignatureUpdater;
}

public interface IComponentUpdater
{
    /// <summary>Looks up the latest version of each component (GitHub, PyPI, npm). Lookup failures become a note, not an exception.</summary>
    Task<IReadOnlyList<ComponentState>> CheckAsync(IReadOnlyList<InstalledComponent> installed, CancellationToken cancellationToken);

    /// <summary>Updates one component the way it was installed. Returns a short result text; throws when it failed.</summary>
    Task<string> UpdateAsync(ComponentState component, IProgress<string>? progress, CancellationToken cancellationToken);
}

/// <summary>State of a signature database (ClamAV): what is on disk and whether it is due for an update.</summary>
public sealed record SignatureDatabaseState(bool Present, string Description, DateTimeOffset? UpdatedUtc, bool UpdaterAvailable);

/// <summary>A signature database Azura keeps up to date (implemented for ClamAV in WebGuard.Detection).</summary>
public interface ISignatureDatabase
{
    string Id { get; }
    string Name { get; }
    SignatureDatabaseState Inspect();
    Task<string> UpdateAsync(CancellationToken cancellationToken);
}
