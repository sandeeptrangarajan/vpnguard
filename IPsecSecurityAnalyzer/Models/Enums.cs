namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Navigation pages supported within the application.
/// </summary>
public enum NavigationPage
{
    Dashboard,
    PcapAnalysis,
    LiveCapture,
    IpsecAnalysis,
    AiAnalysis,
    SecurityAssessment,
    Findings,
    Recommendations,
    Reports,
    History,
    Settings
}

/// <summary>
/// Severity levels for security findings and assessment rules.
/// </summary>
public enum SeverityLevel
{
    Informational = 0,
    Info = 0, // Alias for Informational
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

/// <summary>
/// Overall risk classification levels calculated from deterministic finding weights.
/// </summary>
public enum RiskLevel
{
    Unknown,
    Low,
    Moderate,
    Elevated,
    High,
    Critical
}

/// <summary>
/// Assessment certainty status for an evaluated security finding.
/// </summary>
public enum AssessmentStatus
{
    Confirmed,
    Observed,
    Inferred,
    NotAssessable
}

/// <summary>
/// Categories of security rules evaluated against IPsec/IKE configurations.
/// </summary>
public enum SecurityRuleCategory
{
    IkeVersion,
    Encryption,
    Integrity,
    DiffieHellman,
    PerfectForwardSecrecy,
    ReplayProtection,
    KeyLifetime,
    SecurityAssociation,
    ConfigurationConsistency,
    Coverage
}

/// <summary>
/// Status of security findings for tracking and mitigation workflows.
/// </summary>
public enum FindingStatus
{
    Open,
    Investigating,
    Mitigated,
    FalsePositive,
    Resolved
}

/// <summary>
/// Types of protocol analysis available in the framework.
/// </summary>
public enum AnalysisType
{
    PcapStatic,
    LiveStream,
    IkeHandshake,
    EspTraffic,
    HybridAi
}

/// <summary>
/// Execution status states for the PCAP analyzer engine.
/// </summary>
public enum AnalysisStatus
{
    NotSelected,
    Ready,
    Analyzing,
    Completed,
    Failed,
    Cancelled
}
