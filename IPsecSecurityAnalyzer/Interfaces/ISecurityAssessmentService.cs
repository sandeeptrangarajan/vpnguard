using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Interfaces;

/// <summary>
/// Service interface for the Phase 4 Security Assessment Engine.
/// Evaluates cryptographic parameters, applies deterministic security rules, calculates risk scores,
/// computes assessment coverage, and generates actionable remediation recommendations.
/// </summary>
public interface ISecurityAssessmentService
{
    /// <summary>
    /// Gets the active configurable security policy.
    /// </summary>
    SecurityPolicy CurrentPolicy { get; set; }

    /// <summary>
    /// Gets the most recent security assessment result, or null if no analysis has occurred.
    /// </summary>
    SecurityAssessment? LastAssessment { get; }

    /// <summary>
    /// Event raised whenever a new security assessment is completed.
    /// </summary>
    event EventHandler<SecurityAssessment?>? AssessmentCompleted;

    /// <summary>
    /// Performs a deterministic security assessment on the provided IPsec analysis result.
    /// If no result is passed, assesses the latest result from the IPsec analyzer.
    /// </summary>
    Task<SecurityAssessment> AssessAsync(IpsecAnalysisResult? analysis = null, SecurityPolicy? customPolicy = null);

    /// <summary>
    /// Gets the current comprehensive security assessment.
    /// </summary>
    Task<SecurityAssessment> GetSecurityAssessmentAsync();

    /// <summary>
    /// Gets the list of identified security findings from the latest assessment.
    /// </summary>
    Task<IReadOnlyList<SecurityFinding>> GetFindingsAsync();

    /// <summary>
    /// Gets prioritized remediation recommendations from the latest assessment.
    /// </summary>
    Task<IReadOnlyList<SecurityRecommendation>> GetRecommendationsAsync();
}
