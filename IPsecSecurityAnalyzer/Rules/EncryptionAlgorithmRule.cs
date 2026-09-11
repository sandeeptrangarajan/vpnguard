using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Rules;

/// <summary>
/// Evaluates observed encryption transforms against modern cryptographic policies (NIST / BSI).
/// Distinguishes preferred AEAD (AES-GCM), acceptable CBC modes, and deprecated legacy ciphers (3DES, DES, NULL).
/// </summary>
public class EncryptionAlgorithmRule : ISecurityRule
{
    public string RuleId => "IPSEC-CRYPTO-001";
    public SecurityRuleCategory Category => SecurityRuleCategory.Encryption;
    public string Title => "Weak / Deprecated Encryption Algorithm Detected";
    public string Description => "The IPsec negotiation contains legacy or cryptographically weak encryption transforms (such as 3DES, DES, or NULL) which are vulnerable to Sweet32 collision attacks, meet-in-the-middle attacks, or complete lack of confidentiality.";

    public SecurityFinding? Evaluate(IpsecAnalysisResult analysis, SecurityPolicy policy)
    {
        var encAlg = analysis.EncryptionAlgorithm;
        var weakProposal = analysis.SaProposals.FirstOrDefault(p => policy.WeakEncryptionAlgorithms.Any(w => p.EncryptionAlgorithm.Contains(w, StringComparison.OrdinalIgnoreCase)));

        if (weakProposal != null)
        {
            encAlg = weakProposal.EncryptionAlgorithm;
        }

        if (string.IsNullOrWhiteSpace(encAlg) ||
            encAlg.Equals("Unknown", StringComparison.OrdinalIgnoreCase) ||
            encAlg.Equals("Awaiting analysis", StringComparison.OrdinalIgnoreCase))
        {
            return null; // Unknown parameter reduces coverage, does NOT create false vulnerability
        }

        bool isWeak = policy.WeakEncryptionAlgorithms.Any(w => encAlg.Contains(w, StringComparison.OrdinalIgnoreCase));
        bool isNull = encAlg.Contains("NULL", StringComparison.OrdinalIgnoreCase) || encAlg.Equals("None", StringComparison.OrdinalIgnoreCase);

        if (isNull)
        {
            return new SecurityFinding
            {
                RuleId = RuleId,
                Category = Category,
                Title = "NULL / Unencrypted IPsec Transform Observed",
                Description = "The IPsec Security Association was configured with NULL encryption, meaning user payload data traverses the network in plaintext without confidentiality protection.",
                Severity = SeverityLevel.Critical,
                RiskContribution = policy.CriticalWeight,
                ObservedValue = encAlg,
                ExpectedValue = "AES-256-GCM or AES-128-GCM",
                AffectedParameter = "ESP / IKE Encryption Transform",
                Confidence = 1.0,
                AssessmentStatus = AssessmentStatus.Confirmed,
                Evidence = $"Observed NULL encryption transform '{encAlg}' in SA proposal suite.",
                Recommendation = "Configure strong symmetric encryption immediately. Use AES-256-GCM or AES-128-GCM for both IKE and ESP SAs."
            };
        }

        if (isWeak)
        {
            return new SecurityFinding
            {
                RuleId = RuleId,
                Category = Category,
                Title = Title,
                Description = Description,
                Severity = SeverityLevel.High,
                RiskContribution = policy.HighWeight,
                ObservedValue = encAlg,
                ExpectedValue = "AES-256-GCM, AES-128-GCM, or AES-256-CBC",
                AffectedParameter = "ESP / IKE Encryption Transform",
                Confidence = 1.0,
                AssessmentStatus = AssessmentStatus.Confirmed,
                Evidence = $"Observed legacy cipher '{encAlg}' in IPsec transform negotiations.",
                Recommendation = "Replace 3DES / DES with AES-256-GCM or AES-128-GCM. 3DES uses 64-bit blocks vulnerable to Sweet32 (CVE-2016-2183) and is deprecated by NIST SP 800-131A."
            };
        }

        return null;
    }
}
