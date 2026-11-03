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
}

public enum AppTheme { Dark, Light }

public interface IThemeService
{
    AppTheme Current { get; }
    void Apply(AppTheme theme);
}
