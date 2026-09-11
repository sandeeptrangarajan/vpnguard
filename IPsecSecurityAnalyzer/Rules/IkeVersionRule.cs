using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Rules;

/// <summary>
/// Evaluates the observed IKE protocol version against modern cryptographic standards.
/// Flags legacy IKEv1 protocol usage (RFC 2409) while acknowledging IKEv2 (RFC 7296).
/// </summary>
public class IkeVersionRule : ISecurityRule
{
    public string RuleId => "IPSEC-IKE-001";
    public SecurityRuleCategory Category => SecurityRuleCategory.IkeVersion;
    public string Title => "Legacy IKE Protocol Version Detected";
    public string Description => "The capture indicates the use of IKEv1 (RFC 2409). IKEv1 is deprecated and lacks modern security features such as built-in DoS protection, improved NAT-traversal, efficient Child SA rekeying, and robust authentication mechanisms.";

    public SecurityFinding? Evaluate(IpsecAnalysisResult analysis, SecurityPolicy policy)
    {
        if (string.IsNullOrWhiteSpace(analysis.IkevVersion) ||
            analysis.IkevVersion.Equals("Unknown", StringComparison.OrdinalIgnoreCase) ||
            analysis.IkevVersion.Equals("Awaiting analysis", StringComparison.OrdinalIgnoreCase))
        {
            return null; // Not assessable from capture
        }

        var isWeak = policy.WeakIkeVersions.Any(v => analysis.IkevVersion.Contains(v, StringComparison.OrdinalIgnoreCase));
        if (isWeak)
        {
            return new SecurityFinding
            {
                RuleId = RuleId,
                Category = Category,
                Title = Title,
                Description = Description,
                Severity = SeverityLevel.Medium,
                RiskContribution = policy.MediumWeight,
                ObservedValue = analysis.IkevVersion,
                ExpectedValue = "IKEv2 (RFC 7296)",
                AffectedParameter = "IKE Protocol Version",
                Confidence = 1.0,
                AssessmentStatus = AssessmentStatus.Confirmed,
                Evidence = $"Observed '{analysis.IkevVersion}' in IKE negotiation headers (Packets observed: {analysis.IkePacketCount ?? 0:N0}).",
                Recommendation = "Upgrade the VPN gateway and clients to IKEv2 (RFC 7296). IKEv2 provides streamlined state machines, native NAT-T, robust cookie-based DoS mitigation, and eliminates legacy Phase 1/Phase 2 complexity."
            };
        }

        return null;
    }
}
