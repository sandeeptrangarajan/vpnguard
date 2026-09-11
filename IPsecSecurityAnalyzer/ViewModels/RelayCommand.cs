using System.Windows.Input;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// A parameterless command implementation for MVVM data binding.
/// </summary>
public class RelayCommand : ICommand
{
    private readonly Action _execute;
    private readonly Func<bool>? _canExecute;

    public RelayCommand(Action execute, Func<bool>? canExecute = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }

    public bool CanExecute(object? parameter) => _canExecute == null || _canExecute();

    public void Execute(object? parameter) => _execute();

    public void RaiseCanExecuteChanged()
    {
        if (System.Windows.Application.Current?.Dispatcher != null && !System.Windows.Application.Current.Dispatcher.CheckAccess())
        {
            System.Windows.Application.Current.Dispatcher.Invoke(CommandManager.InvalidateRequerySuggested);
        }
        else
        {
            CommandManager.InvalidateRequerySuggested();
        }
    }
}

/// <summary>
/// A generic parameterized command implementation for MVVM data binding.
/// </summary>
/// <typeparam name="T">Command parameter type.</typeparam>
public class RelayCommand<T> : ICommand
{
    private readonly Action<T?> _execute;
    private readonly Predicate<T?>? _canExecute;

    public RelayCommand(Action<T?> execute, Predicate<T?>? canExecute = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }

    public bool CanExecute(object? parameter)
    {
        if (_canExecute == null) return true;
        if (parameter == null && typeof(T).IsValueType) return _canExecute(default);
        return _canExecute((T?)parameter);
    }

    public void Execute(object? parameter)
    {
        _execute((T?)parameter);
    }

    public void RaiseCanExecuteChanged()
    {
        if (System.Windows.Application.Current?.Dispatcher != null && !System.Windows.Application.Current.Dispatcher.CheckAccess())
        {
            System.Windows.Application.Current.Dispatcher.Invoke(CommandManager.InvalidateRequerySuggested);
        }
        else
        {
            CommandManager.InvalidateRequerySuggested();
        }
    }
}
