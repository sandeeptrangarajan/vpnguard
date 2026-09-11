namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Actionable security remediation guidance derived directly from observed security findings.
/// </summary>
public class SecurityRecommendation
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8].ToUpperInvariant();
    public string RecommendationId
    {
        get => Id;
        set => Id = value;
    }

    public string Title { get; set; } = string.Empty;
    public SeverityLevel Priority { get; set; } = SeverityLevel.Medium;
    public string Recommendation { get; set; } = string.Empty;
    public string RecommendationText
    {
        get => Recommendation;
        set => Recommendation = value;
    }

    public string Reason { get; set; } = string.Empty;
    public string RelatedFindingId { get; set; } = string.Empty;
    public string ObservedEvidence { get; set; } = string.Empty;
    public string AffectedParameter { get; set; } = string.Empty;

    public string FormattedPriority => Priority.ToString().ToUpperInvariant();

    public string PriorityBadgeColor => Priority switch
    {
        SeverityLevel.Critical => "#EF4444",
        SeverityLevel.High => "#F97316",
        SeverityLevel.Medium => "#F59E0B",
        SeverityLevel.Low => "#3B82F6",
        _ => "#6B7280"
    };
}
