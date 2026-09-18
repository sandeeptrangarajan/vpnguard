using System.Windows.Input;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;
using IPsecSecurityAnalyzer.Utilities.Constants;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// Root ViewModel orchestrating sidebar navigation, sub-viewmodels, and header states.
/// </summary>
public class MainViewModel : ViewModelBase
{
    private readonly INavigationService _navigationService;
    private readonly IPcapAnalyzer _pcapAnalyzer;

    private ViewModelBase _currentViewModel;
    private NavigationPage _currentPage = NavigationPage.Dashboard;
    private string _activePcapName = "No PCAP Loaded";
    private bool _hasActivePcap = false;

    // Sub-ViewModels
    public DashboardViewModel DashboardVM { get; }
    public PcapAnalysisViewModel PcapAnalysisVM { get; }
    public LiveCaptureViewModel LiveCaptureVM { get; }
    public IpsecAnalysisViewModel IpsecAnalysisVM { get; }
    public AiAnalysisViewModel AiAnalysisVM { get; }
    public SecurityAssessmentViewModel SecurityAssessmentVM { get; }
    public FindingsViewModel FindingsVM { get; }
    public RecommendationsViewModel RecommendationsVM { get; }
    public ReportsViewModel ReportsVM { get; }
    public HistoryViewModel HistoryVM { get; }
    public SettingsViewModel SettingsVM { get; }

    public MainViewModel(
        INavigationService navigationService,
        IPcapAnalyzer pcapAnalyzer,
        DashboardViewModel dashboardVM,
        PcapAnalysisViewModel pcapAnalysisVM,
        LiveCaptureViewModel liveCaptureVM,
        IpsecAnalysisViewModel ipsecAnalysisVM,
        AiAnalysisViewModel aiAnalysisVM,
        SecurityAssessmentViewModel securityAssessmentVM,
        FindingsViewModel findingsVM,
        RecommendationsViewModel recommendationsVM,
        ReportsViewModel reportsVM,
        HistoryViewModel historyVM,
        SettingsViewModel settingsVM)
    {
        _navigationService = navigationService;
        _pcapAnalyzer = pcapAnalyzer;

        DashboardVM = dashboardVM;
        PcapAnalysisVM = pcapAnalysisVM;
        LiveCaptureVM = liveCaptureVM;
        IpsecAnalysisVM = ipsecAnalysisVM;
        AiAnalysisVM = aiAnalysisVM;
        SecurityAssessmentVM = securityAssessmentVM;
        FindingsVM = findingsVM;
        RecommendationsVM = recommendationsVM;
        ReportsVM = reportsVM;
        HistoryVM = historyVM;
        SettingsVM = settingsVM;

        _currentViewModel = DashboardVM;

        // Navigation Command
        NavigateCommand = new RelayCommand<NavigationPage>(page => _navigationService.NavigateTo(page));

        _navigationService.CurrentPageChanged += (s, page) =>
        {
            CurrentPage = page;
            CurrentViewModel = page switch
            {
                NavigationPage.Dashboard => DashboardVM,
                NavigationPage.PcapAnalysis => PcapAnalysisVM,
                NavigationPage.LiveCapture => LiveCaptureVM,
                NavigationPage.IpsecAnalysis => IpsecAnalysisVM,
                NavigationPage.AiAnalysis => AiAnalysisVM,
                NavigationPage.SecurityAssessment => SecurityAssessmentVM,
                NavigationPage.Findings => FindingsVM,
                NavigationPage.Recommendations => RecommendationsVM,
                NavigationPage.Reports => ReportsVM,
                NavigationPage.History => HistoryVM,
                NavigationPage.Settings => SettingsVM,
                _ => DashboardVM
            };

            if (page == NavigationPage.History)
            {
                _ = HistoryVM.LoadHistoryAsync();
            }
        };

        _pcapAnalyzer.FileChanged += (s, file) =>
        {
            if (file != null)
            {
                ActivePcapName = file.FileName;
                HasActivePcap = true;
            }
            else
            {
                ActivePcapName = "No PCAP Loaded";
                HasActivePcap = false;
            }
        };
    }

    public ViewModelBase CurrentViewModel
    {
        get => _currentViewModel;
        set
        {
            if (SetProperty(ref _currentViewModel, value))
            {
                OnPropertyChanged(nameof(CurrentPageTitle));
                OnPropertyChanged(nameof(CurrentPageSubtitle));
            }
        }
    }

    public NavigationPage CurrentPage
    {
        get => _currentPage;
        set => SetProperty(ref _currentPage, value);
    }

    public string CurrentPageTitle => CurrentPage switch
    {
        NavigationPage.Dashboard => "Executive Dashboard",
        NavigationPage.PcapAnalysis => "PCAP / Packet Capture Analysis",
        NavigationPage.LiveCapture => "Live Network Interface Capture",
        NavigationPage.IpsecAnalysis => "IPsec & IKE Protocol Dissection",
        NavigationPage.AiAnalysis => "AI Traffic Classification & Anomaly Detection",
        NavigationPage.SecurityAssessment => "Comprehensive Security Assessment",
        NavigationPage.Findings => "Security Findings & Vulnerability Matrix",
        NavigationPage.Recommendations => "Prioritized Remediation Recommendations",
        NavigationPage.Reports => "Security Audit Reports & Export",
        NavigationPage.History => "Analysis Session History",
        NavigationPage.Settings => "System Settings & Engine Configuration",
        _ => "IPsec Security Analyzer"
    };

    public string CurrentPageSubtitle => CurrentPage switch
    {
        NavigationPage.Dashboard => "Overview of active packet captures, security posture, and analysis status",
        NavigationPage.PcapAnalysis => "Inspect metadata, capture framing, and static PCAP/PCAPNG files",
        NavigationPage.LiveCapture => "Stream live network traffic from local network interfaces",
        NavigationPage.IpsecAnalysis => "Examine IKEv1/v2 negotiations, ESP cryptographic transforms, and SA parameters",
        NavigationPage.AiAnalysis => "Machine learning protocol inference and anomalous traffic pattern detection",
        NavigationPage.SecurityAssessment => "Cryptographic strength evaluation, compliance validation, and risk metrics",
        NavigationPage.Findings => "Identified weak ciphers, protocol misconfigurations, and security alerts",
        NavigationPage.Recommendations => "Actionable remediation steps mapped to identified findings",
        NavigationPage.Reports => "Generate and export auditor-grade PDF security compliance reports",
        NavigationPage.History => "Search and review previous IPsec analysis sessions and logs",
        NavigationPage.Settings => "Configure analyzer binaries, AI engine, SQLite database, and system preferences",
        _ => "IPsec VPN Protocol Analysis & Security Assessment Framework"
    };

    public string ActivePcapName
    {
        get => _activePcapName;
        set => SetProperty(ref _activePcapName, value);
    }

    public bool HasActivePcap
    {
        get => _hasActivePcap;
        set => SetProperty(ref _hasActivePcap, value);
    }

    public string AppTitle => AppConstants.ApplicationName;
    public string AppSubtitle => AppConstants.ApplicationSubtitle;
    public string SystemStatus => AppConstants.SystemStatusReady;
    public string AppVersion => AppConstants.Version;

    public ICommand NavigateCommand { get; }
}
