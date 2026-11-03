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
