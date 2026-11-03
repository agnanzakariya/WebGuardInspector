using System.Windows.Input;

namespace WebGuard.Presentation.Mvvm;

public interface IRaiseCanExecuteChanged
{
    void RaiseCanExecuteChanged();
}

public sealed class RelayCommand(Action execute, Func<bool>? canExecute = null) : ICommand, IRaiseCanExecuteChanged
{
    public event EventHandler? CanExecuteChanged;
    public bool CanExecute(object? parameter) => canExecute?.Invoke() ?? true;
    public void Execute(object? parameter) { if (CanExecute(parameter)) execute(); }
    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

public sealed class RelayCommand<T>(Action<T?> execute, Func<T?, bool>? canExecute = null) : ICommand, IRaiseCanExecuteChanged
{
    public event EventHandler? CanExecuteChanged;
    public bool CanExecute(object? parameter) => canExecute?.Invoke(Cast(parameter)) ?? true;
    public void Execute(object? parameter) { if (CanExecute(parameter)) execute(Cast(parameter)); }
    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
    private static T? Cast(object? parameter) => parameter is T t ? t : default;
}

/// <summary>Async command that blocks re-entry while running and routes unexpected exceptions to a handler.</summary>
public sealed class AsyncRelayCommand(Func<Task> execute, Func<bool>? canExecute = null, Action<Exception>? onError = null)
    : ICommand, IRaiseCanExecuteChanged
{
    private bool _isRunning;

    public event EventHandler? CanExecuteChanged;

    public bool IsRunning => _isRunning;

    public bool CanExecute(object? parameter) => !_isRunning && (canExecute?.Invoke() ?? true);

    public async void Execute(object? parameter)
    {
        if (!CanExecute(parameter)) return;
        await ExecuteAsync().ConfigureAwait(true);
    }

    public async Task ExecuteAsync()
    {
        _isRunning = true;
        RaiseCanExecuteChanged();
        try
        {
            await execute().ConfigureAwait(true);
        }
#pragma warning disable CA1031 // UI command boundary: report instead of crashing the app.
        catch (Exception ex) when (onError is not null)
        {
            onError(ex);
        }
#pragma warning restore CA1031
        finally
        {
            _isRunning = false;
            RaiseCanExecuteChanged();
        }
    }

    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}
