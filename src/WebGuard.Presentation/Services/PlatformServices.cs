namespace WebGuard.Presentation.Services;

/// <summary>Abstractions over WPF dialogs/clipboard so view models stay platform-independent and testable.</summary>
public interface IFolderPicker
{
    string? PickFolder(string? initialFolder);
}

public interface ISaveFileDialogService
{
    string? PickSavePath(string title, string filter, string defaultFileName);
}

public interface IClipboardService
{
    void SetText(string text);
}

public interface IDialogService
{
    void ShowError(string title, string message);
    void ShowInfo(string title, string message);

    /// <summary>Yes/No question; true when the person chose Yes.</summary>
    bool Confirm(string title, string message);
}

/// <summary>Starts a downloaded installer and closes the app so its files can be replaced.</summary>
public interface IInstallerLauncher
{
    void RunAndExit(string installerPath);
}

/// <summary>Opens a link (e.g. obsidian://open?path=…) with the app registered for it.</summary>
public interface IExternalLauncher
{
    void Open(Uri uri);
}

public enum AppTheme { Dark, Light }

public interface IThemeService
{
    AppTheme Current { get; }
    void Apply(AppTheme theme);
}
