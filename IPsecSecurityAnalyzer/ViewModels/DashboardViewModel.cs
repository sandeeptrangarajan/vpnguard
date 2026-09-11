using System.Linq;
using System.Windows.Input;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for the executive SOC Overview Dashboard.
/// Synchronizes real PCAP analysis and Phase 4 Security Assessment metrics without fake data.
/// </summary>
public class DashboardViewModel : ViewModelBase
{
    private readonly IPcapAnalyzer _pcapAnalyzer;
    private readonly ISecurityAssessmentService _securityService;
    private readonly IFileDialogService _fileDialogService;
    private readonly INavigationService _navigationService;
    private readonly IAnalysisHistoryService? _historyService;
    private readonly IAiAnalysisService? _aiAnalysisService;
    private readonly IAnalysisOrchestrator? _orchestrator;

    private PcapFileInfo? _selectedFile;
    private PcapAnalysisResult? _analysisResult;
    private SecurityAssessment? _securityAssessment;
    private AiAnalysisResult? _aiResult;
    private bool _isAnalyzing;
    private string _statusMessage = "Awaiting analysis";
    private string _errorMessage = string.Empty;
    private int _totalHistoryCount = 0;
    private AnalysisHistory? _latestHistoryRecord;

    public DashboardViewModel(
        IPcapAnalyzer pcapAnalyzer,
        ISecurityAssessmentService securityService,
        IFileDialogService fileDialogService,
        INavigationService navigationService,
        IAnalysisHistoryService? historyService = null,
        IAiAnalysisService? aiAnalysisService = null,
        IAnalysisOrchestrator? orchestrator = null)
    {
        _pcapAnalyzer = pcapAnalyzer;
        _securityService = securityService;
        _fileDialogService = fileDialogService;
        _navigationService = navigationService;
        _historyService = historyService;
        _aiAnalysisService = aiAnalysisService;
        _orchestrator = orchestrator;

        SelectPcapCommand = new RelayCommand(ExecuteSelectPcap, () => !IsAnalyzing);
        AnalyzePcapCommand = new RelayCommand(async () => await ExecuteAnalyzePcapAsync(), () => CanAnalyze);
        NavigateToPcapPageCommand = new RelayCommand(() => _navigationService.NavigateTo(NavigationPage.PcapAnalysis));
        NavigateToIpsecCommand = new RelayCommand(() => _navigationService.NavigateTo(NavigationPage.IpsecAnalysis));
        NavigateToSecurityAssessmentCommand = new RelayCommand(() => _navigationService.NavigateTo(NavigationPage.SecurityAssessment));
        NavigateToFindingsCommand = new RelayCommand(() => _navigationService.NavigateTo(NavigationPage.Findings));
        NavigateToRecommendationsCommand = new RelayCommand(() => _navigationService.NavigateTo(NavigationPage.Recommendations));
        NavigateToHistoryCommand = new RelayCommand(() => _navigationService.NavigateTo(NavigationPage.History));
        NavigateToAiCommand = new RelayCommand(() => _navigationService.NavigateTo(NavigationPage.AiAnalysis));
        NavigateToReportsCommand = new RelayCommand(() => _navigationService.NavigateTo(NavigationPage.Reports));

        _pcapAnalyzer.FileChanged += (s, file) =>
        {
            SelectedFile = file;
            if (file != null)
            {
                StatusMessage = "PCAP loaded — ready for analysis.";
            }
            else
            {
                StatusMessage = "Awaiting analysis";
                AnalysisResult = null;
                SecurityAssessment = null;
                AiResult = null;
            }
        };

        _pcapAnalyzer.AnalysisCompleted += (s, result) =>
        {
            AnalysisResult = result;
            if (result != null)
            {
                StatusMessage = $"PCAP extracted: {result.PacketCount:N0} packets processed ({result.IpsecPacketCount:N0} IPsec).";
            }
        };

        if (_orchestrator != null)
        {
            _orchestrator.AnalysisCompleted += (s, report) =>
            {
                AnalysisResult = _pcapAnalyzer.LastAnalysisResult;
                AiResult = report.HasAiAnalysis
                    ? new AiAnalysisResult
                    {
                        IsModelConnected = true,
                        TrafficType = report.AiTrafficType,
                        Prediction = report.AiPrediction,
                        Confidence = report.AiConfidence,
                        Explanation = report.AiExplanation,
                        Anomalies = report.AiAnomalies.ToList(),
                        TopFeatures = report.TopFeatures.ToList(),
                        Features = report.AiFeatures.ToDictionary(k => k.Key, v => v.Value)
                    }
                    : new AiAnalysisResult { IsModelConnected = false, ErrorMessage = "AI analysis was not available for this run." };

                SecurityAssessment = new SecurityAssessment
                {
                    AssessmentTimestamp = report.HasSecurityAssessment ? report.AnalysisTimestamp : null,
                    OverallRiskScore = report.OverallRiskScore,
                    RiskLevel = report.RiskLevel,
                    AssessmentCoverage = report.AssessmentCoverage,
                    AssessedParameterCount = report.AssessedParameterCount,
                    UnknownParameterCount = report.UnknownParameterCount,
                    Summary = report.AssessmentSummary,
                    Findings = report.Findings.ToList(),
                    Recommendations = report.Recommendations.ToList()
                };
                StatusMessage = $"Analysis completed: {report.TotalPackets:N0} packets processed ({report.IpsecPacketCount:N0} IPsec).";
            };
        }

        _securityService.AssessmentCompleted += (s, assessment) =>
        {
            SecurityAssessment = assessment;
        };

        if (_historyService != null)
        {
            _historyService.HistoryChanged += async (s, e) =>
            {
                await RefreshHistoryMetricsAsync();
            };
            _ = RefreshHistoryMetricsAsync();
        }
    }

    private async Task RefreshHistoryMetricsAsync()
    {
        if (_historyService == null) return;
        TotalHistoryCount = await _historyService.GetHistoryCountAsync();
        LatestHistoryRecord = await _historyService.GetLatestAnalysisAsync();
    }

    public PcapFileInfo? SelectedFile
    {
        get => _selectedFile;
        set
        {
            if (SetProperty(ref _selectedFile, value))
            {
                OnPropertyChanged(nameof(HasSelectedFile));
                OnPropertyChanged(nameof(CanAnalyze));
                OnPropertyChanged(nameof(DisplayFileName));
                OnPropertyChanged(nameof(DisplayFilePath));
                OnPropertyChanged(nameof(DisplayFileSize));
                OnPropertyChanged(nameof(DisplayExtension));
                (AnalyzePcapCommand as RelayCommand)?.RaiseCanExecuteChanged();
            }
        }
    }

    public PcapAnalysisResult? AnalysisResult
    {
        get => _analysisResult;
        set
        {
            if (SetProperty(ref _analysisResult, value))
            {
                OnPropertyChanged(nameof(HasAnalysisResult));
                OnPropertyChanged(nameof(DisplayTotalPackets));
                OnPropertyChanged(nameof(DisplayIpsecPackets));
                OnPropertyChanged(nameof(DisplayIkePackets));
                OnPropertyChanged(nameof(DisplayEspPackets));
                OnPropertyChanged(nameof(DisplaySubTextTotalPackets));
                OnPropertyChanged(nameof(DisplaySubTextIpsec));
                OnPropertyChanged(nameof(DisplaySubTextIke));
                OnPropertyChanged(nameof(DisplaySubTextEsp));
            }
        }
    }

    public SecurityAssessment? SecurityAssessment
    {
        get => _securityAssessment;
        set
        {
            if (SetProperty(ref _securityAssessment, value))
            {
                OnPropertyChanged(nameof(HasSecurityAssessment));
                OnPropertyChanged(nameof(DisplaySecurityScore));
                OnPropertyChanged(nameof(DisplayRiskLevel));
                OnPropertyChanged(nameof(DisplayFindingsSummary));
                OnPropertyChanged(nameof(DisplayHighCriticalFindings));
                OnPropertyChanged(nameof(DisplayCoverage));
                OnPropertyChanged(nameof(RiskBadgeColor));
            }
        }
    }

    public bool HasSelectedFile => _selectedFile != null;
    public bool HasAnalysisResult => _analysisResult != null;
    public bool HasSecurityAssessment => _securityAssessment != null && _securityAssessment.HasAssessment;

    public string DisplayFileName => _selectedFile?.FileName ?? "No file selected";
    public string DisplayFilePath => _selectedFile?.FilePath ?? "Not available";
    public string DisplayFileSize => _selectedFile?.FormattedFileSize ?? "Not available";
    public string DisplayExtension => _selectedFile?.FileExtension?.ToUpperInvariant() ?? "Not available";

    // Overview Cards - Real Analysis Results
    public string DisplayTotalPackets => AnalysisResult != null ? $"{AnalysisResult.PacketCount:N0} Packets" : "No analysis available";
    public string DisplaySubTextTotalPackets => AnalysisResult != null ? $"{AnalysisResult.FormattedTotalBytes} total volume" : (HasSelectedFile ? SelectedFile?.FormattedFileSize ?? "Awaiting capture file" : "Awaiting capture file");

    public string DisplayIpsecPackets => AnalysisResult != null ? $"{AnalysisResult.IpsecPacketCount:N0} Packets" : "Awaiting analysis";
    public string DisplaySubTextIpsec => AnalysisResult != null ? $"{AnalysisResult.FormattedIpsecPercentage} of total traffic" : "0 Active Handshakes";

    public string DisplayIkePackets => AnalysisResult != null ? $"{AnalysisResult.IkePacketCount:N0} Packets" : "Awaiting analysis";
    public string DisplaySubTextIke => AnalysisResult != null ? $"Version: {AnalysisResult.IkeVersion}" : "0 IKE sessions";

    public string DisplayEspPackets => AnalysisResult != null ? $"{AnalysisResult.EspPacketCount:N0} Packets" : "Awaiting analysis";
    public string DisplaySubTextEsp => AnalysisResult != null ? (AnalysisResult.EspSpi != "Unknown" ? $"SPI: {AnalysisResult.EspSpi}" : $"{AnalysisResult.EspPacketCount:N0} ESP frames") : "0 ESP tunnels";

    // Phase 4 Security Assessment Displays
    public string DisplaySecurityScore => HasSecurityAssessment ? $"{_securityAssessment!.OverallRiskScore:F0} / 100" : "No assessment available";
    public string DisplayRiskLevel => HasSecurityAssessment ? _securityAssessment!.RiskLevel.ToString() : "Awaiting analysis";
    public string DisplayFindingsSummary => HasSecurityAssessment ? $"{_securityAssessment!.TotalFindingsCount} Finding(s)" : "No assessment available";
    public string DisplayHighCriticalFindings => HasSecurityAssessment ? $"{_securityAssessment!.CriticalCount} Critical, {_securityAssessment!.HighCount} High" : "Awaiting analysis";
    public string DisplayCoverage => HasSecurityAssessment ? $"{_securityAssessment!.AssessmentCoverage:F0}% Parameter Coverage" : "Awaiting capture analysis";
    public string RiskBadgeColor => HasSecurityAssessment ? _securityAssessment!.RiskBadgeColor : "#6B7280";

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public string ErrorMessage
    {
        get => _errorMessage;
        set
        {
            if (SetProperty(ref _errorMessage, value))
            {
                OnPropertyChanged(nameof(HasError));
            }
        }
    }

    public bool HasError => !string.IsNullOrWhiteSpace(_errorMessage);

    public int TotalHistoryCount
    {
        get => _totalHistoryCount;
        set
        {
            if (SetProperty(ref _totalHistoryCount, value))
            {
                OnPropertyChanged(nameof(DisplayTotalHistoryCount));
                OnPropertyChanged(nameof(HasHistoryRecords));
            }
        }
    }

    public AnalysisHistory? LatestHistoryRecord
    {
        get => _latestHistoryRecord;
        set
        {
            if (SetProperty(ref _latestHistoryRecord, value))
            {
                OnPropertyChanged(nameof(DisplayLatestAnalysis));
                OnPropertyChanged(nameof(DisplayLatestRisk));
                OnPropertyChanged(nameof(DisplayLatestScore));
            }
        }
    }

    public bool HasHistoryRecords => _totalHistoryCount > 0;
    public string DisplayTotalHistoryCount => _totalHistoryCount > 0 ? $"{_totalHistoryCount} Analyses" : "No history recorded";
    public string DisplayLatestAnalysis => _latestHistoryRecord != null ? $"{_latestHistoryRecord.FileName} ({_latestHistoryRecord.FormattedDate})" : "No previous analyses in SQLite";
    public string DisplayLatestRisk => _latestHistoryRecord != null ? $"Risk: {_latestHistoryRecord.RiskLevel}" : "Awaiting analysis";
    public string DisplayLatestScore => _latestHistoryRecord?.SecurityScore.HasValue == true ? $"{_latestHistoryRecord.SecurityScore.Value:F0} / 100" : "N/A";

    public AiAnalysisResult? AiResult
    {
        get => _aiResult;
        set
        {
            if (SetProperty(ref _aiResult, value))
            {
                OnPropertyChanged(nameof(HasAiResult));
                OnPropertyChanged(nameof(DisplayAiTrafficType));
                OnPropertyChanged(nameof(DisplayAiConfidence));
                OnPropertyChanged(nameof(DisplayAiAnomalyStatus));
            }
        }
    }

    public bool HasAiResult => _aiResult != null && _aiResult.IsModelConnected;
    public string DisplayAiTrafficType => _aiResult?.DisplayTrafficType ?? "Awaiting analysis";
    public string DisplayAiConfidence => _aiResult?.DisplayConfidence ?? "Awaiting analysis";
    public string DisplayAiAnomalyStatus => _aiResult != null ? (_aiResult.HasAnomalies ? "Anomaly Detected" : "Normal Traffic") : "Awaiting analysis";

    public bool IsAnalyzing
    {
        get => _isAnalyzing;
        set
        {
            if (SetProperty(ref _isAnalyzing, value))
            {
                OnPropertyChanged(nameof(CanAnalyze));
                OnPropertyChanged(nameof(AnalyzeButtonText));
                (AnalyzePcapCommand as RelayCommand)?.RaiseCanExecuteChanged();
                (SelectPcapCommand as RelayCommand)?.RaiseCanExecuteChanged();
            }
        }
    }

    public bool CanAnalyze => HasSelectedFile && !IsAnalyzing;
    public string AnalyzeButtonText => IsAnalyzing ? "Analyzing..." : "Analyze PCAP";

    public ICommand SelectPcapCommand { get; }
    public ICommand AnalyzePcapCommand { get; }
    public ICommand NavigateToPcapPageCommand { get; }
    public ICommand NavigateToIpsecCommand { get; }
    public ICommand NavigateToSecurityAssessmentCommand { get; }
    public ICommand NavigateToFindingsCommand { get; }
    public ICommand NavigateToRecommendationsCommand { get; }
    public ICommand NavigateToHistoryCommand { get; }
    public ICommand NavigateToAiCommand { get; }
    public ICommand NavigateToReportsCommand { get; }

    private async void ExecuteSelectPcap()
    {
        ErrorMessage = string.Empty;
        try
        {
            var filePath = _fileDialogService.OpenPcapFileDialog();
            if (!string.IsNullOrEmpty(filePath))
            {
                var loadedFile = await _pcapAnalyzer.LoadPcapFileAsync(filePath);
                if (loadedFile != null)
                {
                    SelectedFile = loadedFile;
                    StatusMessage = "PCAP loaded — ready for analysis.";
                }
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Failed to open capture file: {ex.Message}";
        }
    }

    private async Task ExecuteAnalyzePcapAsync()
    {
        if (SelectedFile == null || string.IsNullOrWhiteSpace(SelectedFile.FilePath))
        {
            ErrorMessage = "Please select a PCAP file first.";
            return;
        }

        if (!System.IO.File.Exists(SelectedFile.FilePath))
        {
            ErrorMessage = "Selected PCAP file could not be found.";
            return;
        }

        ErrorMessage = string.Empty;
        IsAnalyzing = true;
        StatusMessage = "Analyzing PCAP...";

        var progress = new Progress<string>(status =>
        {
            StatusMessage = status;
        });

        try
        {
            if (_orchestrator != null)
            {
                var report = await _orchestrator.RunFullAnalysisAsync(SelectedFile.FilePath, progress);
                StatusMessage = "Analysis completed successfully.";
            }
            else
            {
                // Fallback direct execution if orchestrator is not supplied
                StatusMessage = "Running packet analysis...";
                var pcapResult = await _pcapAnalyzer.AnalyzeAsync(SelectedFile.FilePath);
                StatusMessage = "Analysis completed successfully.";
            }
        }
        catch (System.IO.FileNotFoundException)
        {
            ErrorMessage = "Selected PCAP file could not be found.";
            StatusMessage = "Analysis failed.";
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("TShark", StringComparison.OrdinalIgnoreCase))
        {
            ErrorMessage = "TShark is not configured or could not be found.";
            StatusMessage = "Analysis failed.";
        }
        catch (Exception ex)
        {
            ErrorMessage = "PCAP analysis failed. Check the application logs for details.";
            StatusMessage = "Analysis failed.";
            System.Diagnostics.Debug.WriteLine($"[DashboardViewModel] Analysis error: {ex}");
        }
        finally
        {
            IsAnalyzing = false;
        }
    }
}
