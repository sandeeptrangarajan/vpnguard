using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Rules;

/// <summary>
/// Evaluates Perfect Forward Secrecy (PFS) configuration for IPsec Child / Phase 2 SAs.
/// Explains that without PFS, compromise of a long-term private key allows retrospective decryption of past sessions.
/// </summary>
public class PfsRule : ISecurityRule
{
    public string RuleId => "IPSEC-CONFIG-001";
    public SecurityRuleCategory Category => SecurityRuleCategory.PerfectForwardSecrecy;
    public string Title => "Perfect Forward Secrecy (PFS) Disabled";
    public string Description => "Perfect Forward Secrecy (PFS) was not negotiated for the Child / Phase 2 Security Association. Without PFS, all session keys derive directly from the parent IKE SA master secret. If the parent SA or private key is compromised, an attacker can perform retrospective decryption of all recorded past traffic.";

    public SecurityFinding? Evaluate(IpsecAnalysisResult analysis, SecurityPolicy policy)
    {
        // Only evaluate if analysis was performed and IPsec/IKE packets were observed
        if (!analysis.IsAnalyzed || (analysis.IkePacketCount == 0 && analysis.EspPacketCount == 0))
        {
            return null;
        }

        // If explicitly disabled (false)
        if (analysis.PfsEnabled.HasValue && !analysis.PfsEnabled.Value)
        {
            return new SecurityFinding
            {
                RuleId = RuleId,
                Category = Category,
                Title = Title,
                Description = Description,
                Severity = SeverityLevel.Medium,
                RiskContribution = policy.MediumWeight,
                ObservedValue = "PFS Disabled / Not Negotiated",
                ExpectedValue = "PFS Enabled (with DH Group 14+ or Group 19+)",
                AffectedParameter = "IPsec Child SA Perfect Forward Secrecy",
                Confidence = 1.0,
                AssessmentStatus = AssessmentStatus.Confirmed,
                Evidence = "Observed CREATE_CHILD_SA / Quick Mode negotiations without fresh Diffie-Hellman Key Exchange (KE) payloads.",
                Recommendation = "Enable Perfect Forward Secrecy (PFS) on Phase 2 / Child SA configurations on both VPN peers. Ensure a modern DH group (Group 14, 19, or 20) is selected for PFS key derivation."
            };
        }

        return null;
    }
}
