using System.Collections.ObjectModel;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for Comprehensive Security Assessment & Cryptographic Evaluation.
/// Coordinates real-time assessment data, severity breakdowns, and detailed finding inspection.
/// </summary>
public class SecurityAssessmentViewModel : ViewModelBase
{
    private readonly ISecurityAssessmentService _assessmentService;
    private SecurityAssessment _assessment = new();
    private SecurityFinding? _selectedFinding;
    private ObservableCollection<SecurityFinding> _findings = new();

    public SecurityAssessmentViewModel(ISecurityAssessmentService assessmentService)
    {
        _assessmentService = assessmentService;

        _assessmentService.AssessmentCompleted += (s, assessment) =>
        {
            if (assessment != null)
            {
                Assessment = assessment;
            }
            else
            {
                Assessment = new SecurityAssessment();
            }
        };

        _ = LoadAssessmentAsync();
    }

    public SecurityAssessment Assessment
    {
        get => _assessment;
        set
        {
            if (SetProperty(ref _assessment, value))
            {
                OnPropertyChanged(nameof(HasAssessment));
                OnPropertyChanged(nameof(EmptyStateNotice));
                OnPropertyChanged(nameof(DisplayRiskScore));
                OnPropertyChanged(nameof(DisplayRiskLevel));
                OnPropertyChanged(nameof(DisplayCoverage));
                OnPropertyChanged(nameof(DisplayCriticalCount));
                OnPropertyChanged(nameof(DisplayHighCount));
                OnPropertyChanged(nameof(DisplayMediumCount));
                OnPropertyChanged(nameof(DisplayLowCount));
                OnPropertyChanged(nameof(DisplayInformationalCount));
                OnPropertyChanged(nameof(DisplayUnknownCount));
                OnPropertyChanged(nameof(RiskBadgeColor));
                OnPropertyChanged(nameof(SummaryText));

                Findings.Clear();
                if (_assessment.Findings != null)
                {
                    foreach (var f in _assessment.Findings)
                    {
                        Findings.Add(f);
                    }
                    if (Findings.Count > 0)
                    {
                        SelectedFinding = Findings[0];
                    }
                }
            }
        }
    }

    public ObservableCollection<SecurityFinding> Findings
    {
        get => _findings;
        set => SetProperty(ref _findings, value);
    }

    public SecurityFinding? SelectedFinding
    {
        get => _selectedFinding;
        set => SetProperty(ref _selectedFinding, value);
    }

    public bool HasAssessment => _assessment.HasAssessment;
    public string EmptyStateNotice => "Security assessment will be generated automatically after IPsec packet analysis.";

    public string DisplayRiskScore => _assessment.FormattedRiskScore;
    public string DisplayRiskLevel => _assessment.FormattedRiskLevel;
    public string DisplayCoverage => _assessment.FormattedCoverage;
    public string RiskBadgeColor => _assessment.RiskBadgeColor;
    public string SummaryText => !string.IsNullOrWhiteSpace(_assessment.Summary) ? _assessment.Summary : "Awaiting PCAP packet analysis to perform cryptographic assessment.";

    public string DisplayCriticalCount => _assessment.CriticalCount.ToString();
    public string DisplayHighCount => _assessment.HighCount.ToString();
    public string DisplayMediumCount => _assessment.MediumCount.ToString();
    public string DisplayLowCount => _assessment.LowCount.ToString();
    public string DisplayInformationalCount => _assessment.InformationalCount.ToString();
    public string DisplayUnknownCount => _assessment.UnknownParameterCount.ToString();

    private async Task LoadAssessmentAsync()
    {
        Assessment = await _assessmentService.GetSecurityAssessmentAsync();
    }
}
