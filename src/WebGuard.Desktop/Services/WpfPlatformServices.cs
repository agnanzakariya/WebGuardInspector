using System.IO;
using System.Windows;
using Microsoft.Win32;
using WebGuard.Presentation.Services;

namespace WebGuard.Desktop.Services;

public sealed class FolderPicker : IFolderPicker
{
    public string? PickFolder(string? initialFolder)
    {
        var dialog = new OpenFolderDialog { Title = "Select a local source-code folder", Multiselect = false };
        if (!string.IsNullOrEmpty(initialFolder) && Directory.Exists(initialFolder)) dialog.InitialDirectory = initialFolder;
        var owner = Application.Current?.MainWindow;
        var ok = owner is null ? dialog.ShowDialog() : dialog.ShowDialog(owner);
        return ok == true ? dialog.FolderName : null;
    }
}

public sealed class SaveFileDialogService : ISaveFileDialogService
{
    public string? PickSavePath(string title, string filter, string defaultFileName)
    {
        var dialog = new SaveFileDialog
        {
            Title = title,
            Filter = filter,
            FileName = defaultFileName,
            AddExtension = true,
            OverwritePrompt = true,
        };
        var owner = Application.Current?.MainWindow;
        var ok = owner is null ? dialog.ShowDialog() : dialog.ShowDialog(owner);
        return ok == true ? dialog.FileName : null;
    }
}

/// <summary>Opens links such as obsidian://open?path=… with the app registered for the scheme.</summary>
public sealed class ExternalLauncher(IDialogService dialogs) : IExternalLauncher
{
    private static readonly string[] AllowedSchemes = ["obsidian", "https"];

    public void Open(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (!AllowedSchemes.Contains(uri.Scheme, StringComparer.OrdinalIgnoreCase)) return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true })?.Dispose();
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            dialogs.ShowError("Could not open the link", ex.Message + (uri.Scheme == "obsidian" ? " Is Obsidian installed?" : string.Empty));
        }
    }
}

public sealed class ClipboardService : IClipboardService
{
    public void SetText(string text)
    {
        try
        {
            Clipboard.SetText(text);
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            // Clipboard can be locked by another process; copying is best-effort.
        }
    }
}

public sealed class DialogService : IDialogService
{
    public void ShowError(string title, string message) => Show(title, message, MessageBoxImage.Error);

    public void ShowInfo(string title, string message) => Show(title, message, MessageBoxImage.Information);

    private static void Show(string title, string message, MessageBoxImage image)
    {
        var owner = Application.Current?.MainWindow;
        if (owner is { IsLoaded: true })
            MessageBox.Show(owner, message, title, MessageBoxButton.OK, image);
        else
            MessageBox.Show(message, title, MessageBoxButton.OK, image);
    }
}

/// <summary>Swaps the palette dictionary (first merged dictionary in App.xaml) at runtime.</summary>
public sealed class ThemeService : IThemeService
{
    private static readonly Uri DarkUri = new("pack://application:,,,/WebGuard.Desktop;component/Themes/Dark.xaml", UriKind.Absolute);
    private static readonly Uri LightUri = new("pack://application:,,,/WebGuard.Desktop;component/Themes/Light.xaml", UriKind.Absolute);

    public event EventHandler? ThemeChanged;

    public AppTheme Current { get; private set; } = AppTheme.Dark;

    public void Apply(AppTheme theme)
    {
        var dictionaries = Application.Current.Resources.MergedDictionaries;
        var palette = new ResourceDictionary { Source = theme == AppTheme.Dark ? DarkUri : LightUri };
        if (dictionaries.Count > 0) dictionaries[0] = palette;
        else dictionaries.Insert(0, palette);
        Current = theme;
        ThemeChanged?.Invoke(this, EventArgs.Empty);
    }
}
