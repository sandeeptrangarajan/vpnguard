using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Rules;

/// <summary>
/// Evaluates whether IKEv1 Aggressive Mode exchange was used during tunnel establishment.
/// Flags cleartext identity disclosure and pre-shared key (PSK) hash exposure.
/// </summary>
public class AggressiveModeRule : ISecurityRule
{
    public string RuleId => "IPSEC-IKE-002";
    public SecurityRuleCategory Category => SecurityRuleCategory.IkeVersion;
    public string Title => "IKEv1 Aggressive Mode Detected";
    public string Description => "IKEv1 Aggressive Mode compresses Phase 1 negotiation into 3 packets, transmitting authentication hashes and peer identification in cleartext prior to channel encryption. This allows eavesdroppers to capture PSK hashes for offline dictionary attacks.";

    public SecurityFinding? Evaluate(IpsecAnalysisResult analysis, SecurityPolicy policy)
    {
        bool isAggressive = analysis.AggressiveModeDetected ||
                            (analysis.ExchangeType != null && analysis.ExchangeType.Contains("Aggressive", StringComparison.OrdinalIgnoreCase)) ||
                            analysis.Handshakes.Any(h => h.IsAggressiveMode);

        if (isAggressive)
        {
            return new SecurityFinding
            {
                RuleId = RuleId,
                Category = Category,
                Title = Title,
                Description = Description,
                Severity = SeverityLevel.High,
                RiskContribution = policy.HighWeight,
                ObservedValue = "Aggressive Mode (Exchange Type 4)",
                ExpectedValue = "IKEv1 Main Mode (Exchange Type 2) or IKEv2 (IKE_SA_INIT / IKE_AUTH)",
                AffectedParameter = "IKE Phase 1 Exchange Mode",
                Confidence = 1.0,
                AssessmentStatus = AssessmentStatus.Confirmed,
                Evidence = $"Observed IKEv1 Aggressive Mode negotiation exchange in handshake packets. Cleartext peer identity payloads were observed before encryption.",
                Recommendation = "Disable IKEv1 Aggressive Mode immediately across all VPN gateways. Migrate to IKEv2 or restrict legacy tunnels to Main Mode with strong RSA/ECDSA certificate-based authentication."
            };
        }

        return null;
    }
}
