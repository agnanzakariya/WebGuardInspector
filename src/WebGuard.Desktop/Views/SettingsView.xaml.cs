using System.Windows;
using System.Windows.Controls;
using WebGuard.Presentation.ViewModels;

namespace WebGuard.Desktop.Views;

public partial class SettingsView : UserControl
{
    public SettingsView()
    {
        InitializeComponent();
        DataContextChanged += (_, e) =>
        {
            if (e.OldValue is SettingsViewModel old) old.ComponentsRequested -= OnComponentsRequested;
            if (e.NewValue is SettingsViewModel vm) vm.ComponentsRequested += OnComponentsRequested;
        };
        Loaded += (_, _) =>
        {
            if (DataContext is SettingsViewModel { ComponentsScrollPending: true }) OnComponentsRequested(this, EventArgs.Empty);
        };
        Unloaded += (_, _) =>
        {
            if (DataContext is SettingsViewModel vm) vm.ComponentsRequested -= OnComponentsRequested;
        };
    }

    /// <summary>Settings → Components was requested (start-up popup): scroll the card into view once the page is shown.</summary>
    private void OnComponentsRequested(object? sender, EventArgs e) =>
        Dispatcher.BeginInvoke(() =>
        {
            if (!IsLoaded) return;
            ComponentsCard.BringIntoView();
            if (DataContext is SettingsViewModel vm) vm.ComponentsScrollPending = false;
        }, System.Windows.Threading.DispatcherPriority.Loaded);
}
