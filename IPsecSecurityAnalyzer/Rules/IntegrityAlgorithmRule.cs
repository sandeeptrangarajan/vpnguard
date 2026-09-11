using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Rules;

/// <summary>
/// Evaluates observed integrity and hash algorithms against collision resistance standards.
/// Flags broken algorithms (MD5, SHA-1) while validating modern SHA-2 (SHA-256, SHA-384, SHA-512) and AEAD modes.
/// </summary>
public class IntegrityAlgorithmRule : ISecurityRule
{
    public string RuleId => "IPSEC-CRYPTO-002";
    public SecurityRuleCategory Category => SecurityRuleCategory.Integrity;
    public string Title => "Weak / Deprecated Integrity Algorithm Detected";
    public string Description => "The IPsec negotiation utilizes deprecated hash algorithms (such as MD5 or SHA-1) with known practical collision vulnerabilities, compromising packet authenticity and message integrity.";

    public SecurityFinding? Evaluate(IpsecAnalysisResult analysis, SecurityPolicy policy)
    {
        var integAlg = analysis.IntegrityAlgorithm;
        var weakProposal = analysis.SaProposals.FirstOrDefault(p => policy.WeakIntegrityAlgorithms.Any(w => p.IntegrityAlgorithm.Contains(w, StringComparison.OrdinalIgnoreCase)));

        if (weakProposal != null)
        {
            integAlg = weakProposal.IntegrityAlgorithm;
        }

        if (string.IsNullOrWhiteSpace(integAlg) ||
            integAlg.Equals("Unknown", StringComparison.OrdinalIgnoreCase) ||
            integAlg.Equals("Awaiting analysis", StringComparison.OrdinalIgnoreCase) ||
            integAlg.Contains("AEAD", StringComparison.OrdinalIgnoreCase))
        {
            return null; // AEAD handles integrity natively or parameter is not observed
        }

        bool isWeak = policy.WeakIntegrityAlgorithms.Any(w => integAlg.Contains(w, StringComparison.OrdinalIgnoreCase));
        bool isAcceptableSha1 = policy.AcceptableIntegrityAlgorithms.Any(a => integAlg.Contains(a, StringComparison.OrdinalIgnoreCase));

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
                ObservedValue = integAlg,
                ExpectedValue = "HMAC-SHA256-128, HMAC-SHA384-192, or HMAC-SHA512-256",
                AffectedParameter = "IKE / ESP Integrity Algorithm",
                Confidence = 1.0,
                AssessmentStatus = AssessmentStatus.Confirmed,
                Evidence = $"Observed deprecated integrity algorithm '{integAlg}' in SA proposal transforms.",
                Recommendation = "Replace MD5 with HMAC-SHA256, HMAC-SHA384, or HMAC-SHA512. MD5 is cryptographically broken and subject to collision attacks."
            };
        }

        if (isAcceptableSha1)
        {
            return new SecurityFinding
            {
                RuleId = RuleId,
                Category = Category,
                Title = "Legacy SHA-1 Integrity Algorithm in Use",
                Description = "SHA-1 is no longer recommended for cryptographic integrity verification due to theoretical and practical collision vulnerabilities (SHAttered attack).",
                Severity = SeverityLevel.Low,
                RiskContribution = policy.LowWeight,
                ObservedValue = integAlg,
                ExpectedValue = "HMAC-SHA256 or HMAC-SHA384",
                AffectedParameter = "IKE / ESP Integrity Algorithm",
                Confidence = 1.0,
                AssessmentStatus = AssessmentStatus.Confirmed,
                Evidence = $"Observed SHA-1 based integrity algorithm '{integAlg}' in proposal transform.",
                Recommendation = "Plan migration from HMAC-SHA1 to HMAC-SHA256 or use authenticated encryption (AES-GCM) which eliminates standalone integrity hashes."
            };
        }

        return null;
    }
}
