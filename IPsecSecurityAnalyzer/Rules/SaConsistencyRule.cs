using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Rules;

/// <summary>
/// Evaluates consistency across multiple Security Association proposals.
/// Flags configurations offering mixed cryptographic strength (e.g. offering both AES-GCM and weak fallback 3DES).
/// </summary>
public class SaConsistencyRule : ISecurityRule
{
    public string RuleId => "IPSEC-CONFIG-004";
    public SecurityRuleCategory Category => SecurityRuleCategory.SecurityAssociation;
    public string Title => "Inconsistent / Weak Fallback Proposal Suites Detected";
    public string Description => "The peer offered multiple Security Association proposals containing mixed cryptographic levels. Offering legacy fallback suites (e.g. 3DES alongside AES) allows man-in-the-middle downgrade attacks during transform negotiation.";

    public SecurityFinding? Evaluate(IpsecAnalysisResult analysis, SecurityPolicy policy)
    {
        if (analysis.SaProposals.Count <= 1)
        {
            return null; // Single proposal or unobserved
        }

        bool hasStrong = analysis.SaProposals.Any(p => policy.PreferredEncryptionAlgorithms.Any(pref => p.EncryptionAlgorithm.Contains(pref, StringComparison.OrdinalIgnoreCase)));
        bool hasWeak = analysis.SaProposals.Any(p => policy.WeakEncryptionAlgorithms.Any(w => p.EncryptionAlgorithm.Contains(w, StringComparison.OrdinalIgnoreCase)));

        if (hasStrong && hasWeak)
        {
            return new SecurityFinding
            {
                RuleId = RuleId,
                Category = Category,
                Title = Title,
                Description = Description,
                Severity = SeverityLevel.Medium,
                RiskContribution = policy.MediumWeight,
                ObservedValue = $"Mixed Proposals: {analysis.SaProposals.Count} proposals observed (includes both modern and legacy suites)",
                ExpectedValue = "Homogeneous High-Security Proposal List",
                AffectedParameter = "IKE SA Proposal Suite Offerings",
                Confidence = 1.0,
                AssessmentStatus = AssessmentStatus.Observed,
                Evidence = $"Observed {analysis.SaProposals.Count} proposals in IKE_SA_INIT / Phase 1 offer with mixed cryptographic security ratings.",
                Recommendation = "Remove legacy fallback proposals (DES, 3DES, MD5) from the gateway configuration. Enforce only AES-GCM or AES-256-CBC suites to eliminate negotiation downgrade opportunities."
            };
        }

        return null;
    }
}
