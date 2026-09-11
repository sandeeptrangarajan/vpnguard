using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Rules;

/// <summary>
/// Evaluates parameter coverage across observed capture data.
/// Generates informational coverage audit findings when key security parameters could not be observed.
/// Adheres strictly to the principle that unobserved data does NOT equal vulnerability.
/// </summary>
public class UnknownParameterRule : ISecurityRule
{
    public string RuleId => "IPSEC-COV-001";
    public SecurityRuleCategory Category => SecurityRuleCategory.Coverage;
    public string Title => "Unobserved Security Parameters in Packet Capture";
    public string Description => "Certain IPsec / IKE security parameters were not observable in the provided capture file (e.g. negotiation occurred prior to capture start or payloads are encrypted).";

    public SecurityFinding? Evaluate(IpsecAnalysisResult analysis, SecurityPolicy policy)
    {
        if (!analysis.IsAnalyzed)
        {
            return null;
        }

        var unknownParams = new List<string>();

        if (string.IsNullOrWhiteSpace(analysis.IkevVersion) || analysis.IkevVersion.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            unknownParams.Add("IKE Version");

        if (string.IsNullOrWhiteSpace(analysis.EncryptionAlgorithm) || analysis.EncryptionAlgorithm.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            unknownParams.Add("Encryption Algorithm");

        if (string.IsNullOrWhiteSpace(analysis.IntegrityAlgorithm) || analysis.IntegrityAlgorithm.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            unknownParams.Add("Integrity Algorithm");

        if (string.IsNullOrWhiteSpace(analysis.DhGroup) || analysis.DhGroup.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            unknownParams.Add("Diffie-Hellman Group");

        if (!analysis.PfsEnabled.HasValue)
            unknownParams.Add("PFS (Child SA)");

        if (!analysis.ReplayProtectionEnabled.HasValue && analysis.EspSessions.Count == 0)
            unknownParams.Add("Replay Protection Tracking");

        if (unknownParams.Count > 0 && (analysis.IkePacketCount > 0 || analysis.EspPacketCount > 0))
        {
            return new SecurityFinding
            {
                RuleId = RuleId,
                Category = Category,
                Title = "Partial Packet Capture: Unobserved Security Parameters",
                Description = $"The capture contains IPsec traffic, but the following parameter(s) could not be observed in cleartext: {string.Join(", ", unknownParams)}. These parameters could not be assessed and are not classified as vulnerable.",
                Severity = SeverityLevel.Informational,
                RiskContribution = 0.0,
                ObservedValue = $"{unknownParams.Count} parameter(s) unobserved: {string.Join(", ", unknownParams)}",
                ExpectedValue = "Full Handshake Capture with Cleartext Headers",
                AffectedParameter = "Assessment Capture Coverage",
                Confidence = 1.0,
                AssessmentStatus = AssessmentStatus.NotAssessable,
                Evidence = "Parameters were absent from unencrypted initial handshake frames in this specific capture file.",
                Recommendation = "To obtain 100% assessment coverage, capture the full initial IKE negotiation handshake from tunnel establishment (IKE_SA_INIT / Phase 1 Main Mode)."
            };
        }

        return null;
    }
}
