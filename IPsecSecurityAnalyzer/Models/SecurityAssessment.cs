namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Structured security assessment result aggregating findings, deterministic risk scores,
/// assessment coverage, and actionable remediation recommendations.
/// </summary>
public class SecurityAssessment
{
    public double? OverallRiskScore { get; set; }
    public RiskLevel RiskLevel { get; set; } = RiskLevel.Unknown;

    public List<SecurityFinding> Findings { get; set; } = new();
    public List<SecurityRecommendation> Recommendations { get; set; } = new();

    public int AssessedParameterCount { get; set; } = 0;
    public int UnknownParameterCount { get; set; } = 0;
    public double AssessmentCoverage { get; set; } = 0.0;

    public DateTime? AssessmentTimestamp { get; set; }
    public string PolicyName { get; set; } = "NIST / BSI IPsec Security Baseline";
    public string PolicyVersion { get; set; } = "1.0.0";
    public string Summary { get; set; } = string.Empty;
    public string AssessmentSummary
    {
        get => Summary;
        set => Summary = value;
    }
    public List<string> Warnings { get; set; } = new();

    // Section status properties for UI compatibility
    public string CryptographicStrengthStatus { get; set; } = "Awaiting analysis";
    public string ProtocolSecurityStatus { get; set; } = "Awaiting analysis";
    public string KeyExchangeSecurityStatus { get; set; } = "Awaiting analysis";
    public string PfsStatus { get; set; } = "Awaiting analysis";
    public string ReplayProtectionStatus { get; set; } = "Awaiting analysis";
    public string SaConfigurationStatus { get; set; } = "Awaiting analysis";
    public string ConfigurationComplianceStatus { get; set; } = "Awaiting analysis";
    public string MetadataExposureStatus { get; set; } = "Awaiting analysis";

    // Computed Severity breakdown
    public int CriticalCount => Findings.Count(f => f.Severity == SeverityLevel.Critical);
    public int HighCount => Findings.Count(f => f.Severity == SeverityLevel.High);
    public int MediumCount => Findings.Count(f => f.Severity == SeverityLevel.Medium);
    public int LowCount => Findings.Count(f => f.Severity == SeverityLevel.Low);
    public int InformationalCount => Findings.Count(f => f.Severity == SeverityLevel.Informational);
    public int TotalFindingsCount => Findings.Count;

    public bool HasAssessment => OverallRiskScore.HasValue && AssessmentTimestamp.HasValue;

    // Display helpers for WPF data binding
    public string FormattedRiskScore => OverallRiskScore.HasValue ? $"{OverallRiskScore.Value:F0} / 100" : "Not available";
    public string FormattedRiskLevel => RiskLevel != RiskLevel.Unknown ? RiskLevel.ToString() : "Awaiting analysis";
    public string FormattedCoverage => OverallRiskScore.HasValue ? $"{AssessmentCoverage:F0}%" : "0%";
    public string FormattedTimestamp => AssessmentTimestamp.HasValue ? AssessmentTimestamp.Value.ToString("yyyy-MM-dd HH:mm:ss") : "Not available";

    public string RiskBadgeColor => RiskLevel switch
    {
        RiskLevel.Critical => "#EF4444",
        RiskLevel.High => "#F97316",
        RiskLevel.Elevated => "#F59E0B",
        RiskLevel.Moderate => "#EAB308",
        RiskLevel.Low => "#10B981",
        _ => "#6B7280"
    };
}
