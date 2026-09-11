namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Actionable remediation recommendation mapped to security findings.
/// </summary>
public class Recommendation
{
    public string Id { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Priority { get; set; } = "Medium";
    public SeverityLevel Severity { get; set; } = SeverityLevel.Medium;
    public string RelatedFindingId { get; set; } = string.Empty;
    public string Status { get; set; } = "Pending";

    public string FormattedSeverity => Severity.ToString().ToUpperInvariant();
}
