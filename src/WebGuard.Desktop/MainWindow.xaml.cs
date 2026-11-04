using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using WebGuard.Desktop.Services;
using WebGuard.Presentation.Services;
using WebGuard.Presentation.ViewModels;

namespace WebGuard.Desktop;

public partial class MainWindow : Window
{
    private readonly ThemeService _theme;

    public MainWindow(ShellViewModel shell, ThemeService theme)
    {
        ArgumentNullException.ThrowIfNull(shell);
        ArgumentNullException.ThrowIfNull(theme);
        InitializeComponent();
        DataContext = shell;
        _theme = theme;
        _theme.ThemeChanged += (_, _) => NativeMethods.SetDarkTitleBar(this, _theme.Current == AppTheme.Dark);
        SourceInitialized += (_, _) => NativeMethods.SetDarkTitleBar(this, _theme.Current == AppTheme.Dark);
        Title = $"{shell.AppName} {shell.VersionText}";
        FitToWorkArea(SystemParameters.WorkArea);
        // While the setup wizard is open the app's shortcuts (F5 scan, Ctrl+O/E/F) must not reach the pages behind it.
        PreviewKeyDown += (_, e) =>
        {
            if (shell.IsSetupRequired && (e.Key is Key.F5 || Keyboard.Modifiers == ModifierKeys.Control && e.Key is Key.O or Key.E or Key.F))
                e.Handled = true;
        };
    }

    /// <summary>
    /// Keeps the whole window, title bar included, on screen. On small or high-scaling displays (e.g. 1920×1080 at 125%
    /// is a 1536×816 work area) the designed 1480×920 window would be centred with its caption buttons above the
    /// top edge, so the window is shrunk to the work area and starts maximized instead.
    /// </summary>
    private void FitToWorkArea(Rect area)
    {
        var tooSmall = Width > area.Width || Height > area.Height;
        MinWidth = Math.Min(MinWidth, area.Width);
        MinHeight = Math.Min(MinHeight, area.Height);
        Width = Math.Min(Width, area.Width);
        Height = Math.Min(Height, area.Height);
        WindowStartupLocation = WindowStartupLocation.Manual;
        Left = area.Left + (area.Width - Width) / 2;
        Top = area.Top + (area.Height - Height) / 2;
        if (tooSmall) WindowState = WindowState.Maximized;
    }

    /// <summary>Ctrl+F: focus the search box of the current page (if it has one).</summary>
    private void OnFind(object sender, ExecutedRoutedEventArgs e)
    {
        var box = FindSearchBox(PageHost);
        if (box is null) return;
        box.Focus();
        box.SelectAll();
        e.Handled = true;
    }

    private static TextBox? FindSearchBox(DependencyObject root)
    {
        var count = VisualTreeHelper.GetChildrenCount(root);
        for (var i = 0; i < count; i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is TextBox tb && AutomationProperties.GetAutomationId(tb) == "SearchBox" && tb.IsVisible) return tb;
            var nested = FindSearchBox(child);
            if (nested is not null) return nested;
        }
        return null;
    }
}
