using System.Windows;
using System.Windows.Threading;
using Microsoft.Extensions.DependencyInjection;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Services;
using IPsecSecurityAnalyzer.ViewModels;
using IPsecSecurityAnalyzer.Views;

namespace IPsecSecurityAnalyzer;

/// <summary>
/// Application entry point configuring Dependency Injection, service lifetimes, and error handling.
/// </summary>
public partial class App : Application
{
    private ServiceProvider? _serviceProvider;

    public App()
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnCurrentDomainUnhandledException;
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var serviceCollection = new ServiceCollection();
        ConfigureServices(serviceCollection);

        _serviceProvider = serviceCollection.BuildServiceProvider();

        var mainWindow = _serviceProvider.GetRequiredService<MainWindow>();
        mainWindow.Show();
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        // Core Services
        services.AddSingleton<ISettingsService, SettingsService>();
        services.AddSingleton<ITsharkService, TsharkService>();
        services.AddSingleton<INavigationService, NavigationService>();
        services.AddSingleton<IPcapAnalyzer, PcapAnalyzer>();
        services.AddSingleton<ILiveCaptureService, LiveCaptureService>();
        services.AddSingleton<IIpsecAnalyzer, IpsecAnalyzer>();
        services.AddSingleton<ISecurityAssessmentService, SecurityAssessmentService>();
        services.AddSingleton<IAiAnalysisService, AiAnalysisService>();
        services.AddSingleton<IReportService, ReportService>();
        services.AddSingleton<IAnalysisHistoryService, AnalysisHistoryService>();
        services.AddSingleton<IFileDialogService, FileDialogService>();
        services.AddSingleton<IAnalysisOrchestrator, AnalysisOrchestrator>();

        // ViewModels
        services.AddSingleton<DashboardViewModel>();
        services.AddSingleton<PcapAnalysisViewModel>();
        services.AddSingleton<LiveCaptureViewModel>();
        services.AddSingleton<IpsecAnalysisViewModel>();
        services.AddSingleton<AiAnalysisViewModel>();
        services.AddSingleton<SecurityAssessmentViewModel>();
        services.AddSingleton<FindingsViewModel>();
        services.AddSingleton<RecommendationsViewModel>();
        services.AddSingleton<ReportsViewModel>();
        services.AddSingleton<HistoryViewModel>();
        services.AddSingleton<SettingsViewModel>();
        services.AddSingleton<MainViewModel>();

        // Views
        services.AddTransient<MainWindow>();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _serviceProvider?.Dispose();
        base.OnExit(e);
    }

    private string? _lastErrorMessage;
    private DateTime _lastErrorTime = DateTime.MinValue;

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        var now = DateTime.Now;
        if (_lastErrorMessage == e.Exception.Message && (now - _lastErrorTime).TotalSeconds < 2)
        {
            e.Handled = true;
            return;
        }

        _lastErrorMessage = e.Exception.Message;
        _lastErrorTime = now;

        MessageBox.Show(
            $"An unexpected error occurred:\n\n{e.Exception.Message}",
            "IPsec Security Analyzer - Error",
            MessageBoxButton.OK,
            MessageBoxImage.Warning
        );
        e.Handled = true;
    }

    private void OnCurrentDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception ex)
        {
            MessageBox.Show(
                $"A critical system error occurred:\n\n{ex.Message}",
                "IPsec Security Analyzer - Fatal Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );
        }
    }
}
