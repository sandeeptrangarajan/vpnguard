using System.Collections.ObjectModel;
using System.Windows.Input;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for Security Findings and Vulnerability Matrix.
/// Supports filtering by severity level and rule category, detailed evidence inspector, and status tracking.
/// </summary>
public class FindingsViewModel : ViewModelBase
{
    private readonly ISecurityAssessmentService _securityService;
    private List<SecurityFinding> _allFindings = new();
    private ObservableCollection<SecurityFinding> _filteredFindings = new();
    private SecurityFinding? _selectedFinding;

    private string _selectedSeverityFilter = "All";
    private string _selectedCategoryFilter = "All";

    public FindingsViewModel(ISecurityAssessmentService securityService)
    {
        _securityService = securityService;

        FilterAllCommand = new RelayCommand(() => SelectedSeverityFilter = "All");
        FilterCriticalCommand = new RelayCommand(() => SelectedSeverityFilter = "Critical");
        FilterHighCommand = new RelayCommand(() => SelectedSeverityFilter = "High");
        FilterMediumCommand = new RelayCommand(() => SelectedSeverityFilter = "Medium");
        FilterLowCommand = new RelayCommand(() => SelectedSeverityFilter = "Low");
        FilterInfoCommand = new RelayCommand(() => SelectedSeverityFilter = "Informational");

        _securityService.AssessmentCompleted += (s, assessment) =>
        {
            LoadFindingsFromAssessment(assessment);
        };

        _ = LoadFindingsAsync();
    }

    public ObservableCollection<SecurityFinding> Findings
    {
        get => _filteredFindings;
        set => SetProperty(ref _filteredFindings, value);
    }

    public SecurityFinding? SelectedFinding
    {
        get => _selectedFinding;
        set => SetProperty(ref _selectedFinding, value);
    }

    public string SelectedSeverityFilter
    {
        get => _selectedSeverityFilter;
        set
        {
            if (SetProperty(ref _selectedSeverityFilter, value))
            {
                ApplyFilter();
            }
        }
    }

    public string SelectedCategoryFilter
    {
        get => _selectedCategoryFilter;
        set
        {
            if (SetProperty(ref _selectedCategoryFilter, value))
            {
                ApplyFilter();
            }
        }
    }

    public bool HasFindings => _allFindings.Count > 0;
    public bool HasFilteredFindings => _filteredFindings.Count > 0;

    public int TotalFindingsCount => _allFindings.Count;
    public int CriticalCount => _allFindings.Count(f => f.Severity == SeverityLevel.Critical);
    public int HighCount => _allFindings.Count(f => f.Severity == SeverityLevel.High);
    public int MediumCount => _allFindings.Count(f => f.Severity == SeverityLevel.Medium);
    public int LowCount => _allFindings.Count(f => f.Severity == SeverityLevel.Low);
    public int InformationalCount => _allFindings.Count(f => f.Severity == SeverityLevel.Informational);

    public ICommand FilterAllCommand { get; }
    public ICommand FilterCriticalCommand { get; }
    public ICommand FilterHighCommand { get; }
    public ICommand FilterMediumCommand { get; }
    public ICommand FilterLowCommand { get; }
    public ICommand FilterInfoCommand { get; }

    private async Task LoadFindingsAsync()
    {
        var assessment = await _securityService.GetSecurityAssessmentAsync();
        LoadFindingsFromAssessment(assessment);
    }

    private void LoadFindingsFromAssessment(SecurityAssessment? assessment)
    {
        _allFindings = assessment?.Findings != null ? new List<SecurityFinding>(assessment.Findings) : new List<SecurityFinding>();
        ApplyFilter();
        OnPropertyChanged(nameof(HasFindings));
        OnPropertyChanged(nameof(TotalFindingsCount));
        OnPropertyChanged(nameof(CriticalCount));
        OnPropertyChanged(nameof(HighCount));
        OnPropertyChanged(nameof(MediumCount));
        OnPropertyChanged(nameof(LowCount));
        OnPropertyChanged(nameof(InformationalCount));
    }

    private void ApplyFilter()
    {
        var filtered = _allFindings.AsEnumerable();

        if (SelectedSeverityFilter != "All")
        {
            if (Enum.TryParse<SeverityLevel>(SelectedSeverityFilter, true, out var sev))
            {
                filtered = filtered.Where(f => f.Severity == sev);
            }
        }

        if (SelectedCategoryFilter != "All")
        {
            filtered = filtered.Where(f => f.Category.ToString().Equals(SelectedCategoryFilter, StringComparison.OrdinalIgnoreCase));
        }

        Findings.Clear();
        foreach (var item in filtered)
        {
            Findings.Add(item);
        }

        if (Findings.Count > 0)
        {
            SelectedFinding = Findings[0];
        }
        else
        {
            SelectedFinding = null;
        }

        OnPropertyChanged(nameof(HasFilteredFindings));
    }
}
