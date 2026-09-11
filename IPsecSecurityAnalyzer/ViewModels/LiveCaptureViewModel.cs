using System.Collections.ObjectModel;
using System.Windows.Input;
using IPsecSecurityAnalyzer.Interfaces;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for Live Network Interface Capture.
/// </summary>
public class LiveCaptureViewModel : ViewModelBase
{
    private readonly ILiveCaptureService _liveCaptureService;

    private ObservableCollection<string> _availableInterfaces = new();
    private string? _selectedInterface;
    private string _captureDuration = "60";
    private string _captureStatus = "Live packet capture requires Npcap/WinPcap kernel drivers with elevated permissions. Static PCAP analysis is recommended.";
    private string _packetCountStatus = "Not connected";

    public LiveCaptureViewModel(ILiveCaptureService liveCaptureService)
    {
        _liveCaptureService = liveCaptureService;

        StartCaptureCommand = new RelayCommand(ExecuteStartCapture, () => false);
        StopCaptureCommand = new RelayCommand(ExecuteStopCapture, () => false);
        RefreshInterfacesCommand = new RelayCommand(async () => await LoadInterfacesAsync());

        _ = LoadInterfacesAsync();
    }

    public ObservableCollection<string> AvailableInterfaces
    {
        get => _availableInterfaces;
        set => SetProperty(ref _availableInterfaces, value);
    }

    public string? SelectedInterface
    {
        get => _selectedInterface;
        set => SetProperty(ref _selectedInterface, value);
    }

    public string CaptureDuration
    {
        get => _captureDuration;
        set => SetProperty(ref _captureDuration, value);
    }

    public string CaptureStatus
    {
        get => _captureStatus;
        set => SetProperty(ref _captureStatus, value);
    }

    public string PacketCountStatus
    {
        get => _packetCountStatus;
        set => SetProperty(ref _packetCountStatus, value);
    }

    public ICommand StartCaptureCommand { get; }
    public ICommand StopCaptureCommand { get; }
    public ICommand RefreshInterfacesCommand { get; }

    private async Task LoadInterfacesAsync()
    {
        try
        {
            var ifaces = await _liveCaptureService.GetAvailableInterfacesAsync();
            AvailableInterfaces.Clear();
            foreach (var iface in ifaces)
            {
                AvailableInterfaces.Add(iface);
            }

            if (AvailableInterfaces.Count > 0)
            {
                SelectedInterface = AvailableInterfaces[0];
            }
        }
        catch
        {
            AvailableInterfaces.Clear();
            AvailableInterfaces.Add("Local Interface Discovery Restricted");
            SelectedInterface = AvailableInterfaces[0];
        }
    }

    private void ExecuteStartCapture() { }
    private void ExecuteStopCapture() { }
}
