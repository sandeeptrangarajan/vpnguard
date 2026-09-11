namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Represents an identified security vulnerability, weak configuration, or compliance finding.
/// Contains complete deterministic evidence referencing actual Phase 3 protocol values.
/// </summary>
public class SecurityFinding
{
    public string FindingId { get; set; } = Guid.NewGuid().ToString("N")[..8].ToUpperInvariant();
    public string Id
    {
        get => FindingId;
        set => FindingId = value;
    }

    public string RuleId { get; set; } = string.Empty;
    public SecurityRuleCategory Category { get; set; } = SecurityRuleCategory.IkeVersion;
    public string CategoryName => Category.ToString();

    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public SeverityLevel Severity { get; set; } = SeverityLevel.Informational;
    public double RiskContribution { get; set; } = 0.0;

    public string Evidence { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
    public double Confidence { get; set; } = 1.0;
    public AssessmentStatus AssessmentStatus { get; set; } = AssessmentStatus.Observed;

    public string ObservedValue { get; set; } = string.Empty;
    public string ExpectedValue { get; set; } = string.Empty;
    public string AffectedParameter { get; set; } = string.Empty;

    public FindingStatus Status { get; set; } = FindingStatus.Open;

    // Display helpers for WPF UI binding
    public string FormattedSeverity => Severity.ToString().ToUpperInvariant();
    public string FormattedRiskContribution => $"+{RiskContribution:F1}";
    public string FormattedConfidence => $"{Confidence * 100:F0}% ({AssessmentStatus})";
    public string FormattedStatus => Status.ToString();

    public string SeverityBadgeColor => Severity switch
    {
        SeverityLevel.Critical => "#EF4444", // Red
        SeverityLevel.High => "#F97316",     // Orange
        SeverityLevel.Medium => "#F59E0B",   // Amber
        SeverityLevel.Low => "#3B82F6",      // Blue
        _ => "#6B7280"                       // Gray
    };
}
