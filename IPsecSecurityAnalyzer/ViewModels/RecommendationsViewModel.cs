using System.Collections.ObjectModel;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for Prioritized Security Remediation Recommendations.
/// Translates identified cryptographic and protocol findings into actionable remediation guidance.
/// </summary>
public class RecommendationsViewModel : ViewModelBase
{
    private readonly ISecurityAssessmentService _securityService;
    private ObservableCollection<SecurityRecommendation> _recommendations = new();
    private SecurityRecommendation? _selectedRecommendation;

    public RecommendationsViewModel(ISecurityAssessmentService securityService)
    {
        _securityService = securityService;

        _securityService.AssessmentCompleted += (s, assessment) =>
        {
            LoadRecommendationsFromAssessment(assessment);
        };

        _ = LoadRecommendationsAsync();
    }

    public ObservableCollection<SecurityRecommendation> Recommendations
    {
        get => _recommendations;
        set => SetProperty(ref _recommendations, value);
    }

    public SecurityRecommendation? SelectedRecommendation
    {
        get => _selectedRecommendation;
        set => SetProperty(ref _selectedRecommendation, value);
    }

    public bool HasRecommendations => _recommendations.Count > 0;
    public string EmptyStateText => "No recommendations available. Load and analyze an IPsec PCAP file to generate remediation steps.";

    public int TotalRecommendationsCount => _recommendations.Count;
    public int CriticalPriorityCount => _recommendations.Count(r => r.Priority == SeverityLevel.Critical);
    public int HighPriorityCount => _recommendations.Count(r => r.Priority == SeverityLevel.High);
    public int MediumPriorityCount => _recommendations.Count(r => r.Priority == SeverityLevel.Medium);

    private async Task LoadRecommendationsAsync()
    {
        var assessment = await _securityService.GetSecurityAssessmentAsync();
        LoadRecommendationsFromAssessment(assessment);
    }

    private void LoadRecommendationsFromAssessment(SecurityAssessment? assessment)
    {
        Recommendations.Clear();
        if (assessment?.Recommendations != null)
        {
            foreach (var rec in assessment.Recommendations)
            {
                Recommendations.Add(rec);
            }
            if (Recommendations.Count > 0)
            {
                SelectedRecommendation = Recommendations[0];
            }
        }
        OnPropertyChanged(nameof(HasRecommendations));
        OnPropertyChanged(nameof(TotalRecommendationsCount));
        OnPropertyChanged(nameof(CriticalPriorityCount));
        OnPropertyChanged(nameof(HighPriorityCount));
        OnPropertyChanged(nameof(MediumPriorityCount));
    }
}
