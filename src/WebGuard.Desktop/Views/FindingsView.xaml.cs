using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using WebGuard.Presentation.ViewModels;

namespace WebGuard.Desktop.Views;

public partial class FindingsView : UserControl
{
    private FindingsViewModel? _viewModel;

    public FindingsView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (_viewModel is not null) _viewModel.PropertyChanged -= OnViewModelPropertyChanged;
        _viewModel = e.NewValue as FindingsViewModel;
        if (_viewModel is not null) _viewModel.PropertyChanged += OnViewModelPropertyChanged;
    }

    /// <summary>When an analysis finishes, scroll the detail panel so the result is visible below the scanner details.</summary>
    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(FindingsViewModel.IsAnalyzing) || _viewModel is not { IsAnalyzing: false, HasCurrentAnalysis: true }) return;
        Dispatcher.BeginInvoke(DispatcherPriority.Loaded, () => AiResultPanel.BringIntoView());
    }
}
