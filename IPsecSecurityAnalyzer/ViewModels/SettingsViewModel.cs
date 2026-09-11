using System.Windows.Input;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for System Configuration, Engine Paths, and Environment Status.
/// </summary>
public class SettingsViewModel : ViewModelBase
{
    private readonly ISettingsService _settingsService;
    private readonly ITsharkService _tsharkService;
    private readonly IFileDialogService _fileDialogService;

    private ApplicationSettings _settings = new();
    private string _statusMessage = string.Empty;
    private string _tsharkTestStatus = string.Empty;
    private string _tsharkVersionInfo = string.Empty;
    private bool _isTsharkTested = false;
    private bool _isTsharkValid = false;
    private bool _isTestingTshark = false;

    public SettingsViewModel(
        ISettingsService settingsService,
        ITsharkService tsharkService,
        IFileDialogService fileDialogService)
    {
        _settingsService = settingsService;
        _tsharkService = tsharkService;
        _fileDialogService = fileDialogService;

        SaveSettingsCommand = new RelayCommand(async () => await SaveSettingsAsync());
        BrowseTsharkPathCommand = new RelayCommand(ExecuteBrowseTsharkPath);
        TestTsharkCommand = new RelayCommand(async () => await ExecuteTestTsharkAsync(), () => !IsTestingTshark);

        _ = InitializeSettingsAsync();
    }

    public ApplicationSettings Settings
    {
        get => _settings;
        set => SetProperty(ref _settings, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public string TsharkTestStatus
    {
        get => _tsharkTestStatus;
        set => SetProperty(ref _tsharkTestStatus, value);
    }

    public string TsharkVersionInfo
    {
        get => _tsharkVersionInfo;
        set => SetProperty(ref _tsharkVersionInfo, value);
    }

    public bool IsTsharkTested
    {
        get => _isTsharkTested;
        set => SetProperty(ref _isTsharkTested, value);
    }

    public bool IsTsharkValid
    {
        get => _isTsharkValid;
        set => SetProperty(ref _isTsharkValid, value);
    }

    public bool IsTestingTshark
    {
        get => _isTestingTshark;
        set => SetProperty(ref _isTestingTshark, value);
    }

    public ICommand SaveSettingsCommand { get; }
    public ICommand BrowseTsharkPathCommand { get; }
    public ICommand TestTsharkCommand { get; }

    private async Task InitializeSettingsAsync()
    {
        Settings = await _settingsService.LoadSettingsAsync();
        await ExecuteTestTsharkAsync();
    }

    private void ExecuteBrowseTsharkPath()
    {
        var exePath = _fileDialogService.OpenExecutableFileDialog("Select TShark Executable (tshark.exe)");
        if (!string.IsNullOrEmpty(exePath))
        {
            Settings.TsharkPath = exePath;
            OnPropertyChanged(nameof(Settings));
            _ = ExecuteTestTsharkAsync();
        }
    }

    private async Task ExecuteTestTsharkAsync()
    {
        IsTestingTshark = true;
        TsharkTestStatus = "Probing TShark...";
        TsharkVersionInfo = string.Empty;

        try
        {
            var version = await _tsharkService.GetTsharkVersionAsync(Settings.TsharkPath);
            IsTsharkTested = true;

            if (!string.IsNullOrWhiteSpace(version))
            {
                IsTsharkValid = true;
                TsharkTestStatus = "TShark detected";
                TsharkVersionInfo = $"Version: {version}";
                Settings.AnalyzerStatus = $"TShark active ({version.Split(',')[0].Trim()})";
            }
            else
            {
                IsTsharkValid = false;
                TsharkTestStatus = "TShark not found";
                TsharkVersionInfo = "TShark was not found. Install Wireshark or configure the TShark path in Settings.";
                Settings.AnalyzerStatus = "TShark not found (Install Wireshark or configure path)";
            }
        }
        catch (Exception ex)
        {
            IsTsharkTested = true;
            IsTsharkValid = false;
            TsharkTestStatus = "TShark error";
            TsharkVersionInfo = $"Failed to execute tshark: {ex.Message}";
        }
        finally
        {
            IsTestingTshark = false;
        }
    }

    private async Task SaveSettingsAsync()
    {
        await _settingsService.SaveSettingsAsync(Settings);
        StatusMessage = "Settings saved successfully.";
    }
}
