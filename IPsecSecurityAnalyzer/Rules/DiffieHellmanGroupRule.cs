using System.Text.RegularExpressions;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Rules;

/// <summary>
/// Evaluates observed Diffie-Hellman key exchange groups against NIST SP 800-57 guidelines.
/// Flags legacy small-modulus groups (Group 1: 768-bit, Group 2: 1024-bit, Group 5: 1536-bit) while recommending Group 14+ / 19+.
/// </summary>
public class DiffieHellmanGroupRule : ISecurityRule
{
    public string RuleId => "IPSEC-CRYPTO-003";
    public SecurityRuleCategory Category => SecurityRuleCategory.DiffieHellman;
    public string Title => "Weak Diffie-Hellman Group Detected";
    public string Description => "The key exchange uses a Diffie-Hellman group with modulus size under 2048 bits (e.g. Group 1: 768-bit, Group 2: 1024-bit). Sub-2048-bit MODP groups are susceptible to discrete logarithm precomputation attacks (Logjam / Number Field Sieve).";

    public SecurityFinding? Evaluate(IpsecAnalysisResult analysis, SecurityPolicy policy)
    {
        var dhStr = analysis.DhGroup;
        var weakProposal = analysis.SaProposals.FirstOrDefault(p => policy.WeakDhGroups.Any(w => p.DhGroup.Contains($"Group {w}", StringComparison.OrdinalIgnoreCase) || p.DhGroup.Equals(w.ToString())));

        if (weakProposal != null)
        {
            dhStr = weakProposal.DhGroup;
        }

        if (string.IsNullOrWhiteSpace(dhStr) ||
            dhStr.Equals("Unknown", StringComparison.OrdinalIgnoreCase) ||
            dhStr.Equals("Awaiting analysis", StringComparison.OrdinalIgnoreCase))
        {
            return null; // Not observed -> reduces coverage, no false positive
        }

        int groupNum = ExtractGroupNumber(dhStr);

        if (groupNum > 0 && policy.WeakDhGroups.Contains(groupNum))
        {
            return new SecurityFinding
            {
                RuleId = RuleId,
                Category = Category,
                Title = Title,
                Description = Description,
                Severity = SeverityLevel.High,
                RiskContribution = policy.HighWeight,
                ObservedValue = dhStr,
                ExpectedValue = "Group 14 (2048-bit MODP), Group 19 (256-bit ECP), Group 20 (384-bit ECP), or Group 21",
                AffectedParameter = "Diffie-Hellman Key Exchange Group",
                Confidence = 1.0,
                AssessmentStatus = AssessmentStatus.Confirmed,
                Evidence = $"Observed '{dhStr}' in IKE Key Exchange negotiation.",
                Recommendation = "Configure Diffie-Hellman Group 14 (2048-bit MODP) as the minimum baseline, or Group 19 (256-bit Random ECP) for optimal performance and security. NIST SP 800-57 disallows DH keys < 2048 bits."
            };
        }

        if (groupNum == 5) // 1536-bit MODP
        {
            return new SecurityFinding
            {
                RuleId = RuleId,
                Category = Category,
                Title = "Legacy Diffie-Hellman Group 5 (1536-bit) Observed",
                Description = "DH Group 5 provides approximately 90 bits of symmetric security equivalence, which is below the NIST-mandated 112-bit minimum.",
                Severity = SeverityLevel.Low,
                RiskContribution = policy.LowWeight,
                ObservedValue = dhStr,
                ExpectedValue = "Group 14 (2048-bit MODP) or Group 19 (256-bit ECP)",
                AffectedParameter = "Diffie-Hellman Key Exchange Group",
                Confidence = 1.0,
                AssessmentStatus = AssessmentStatus.Confirmed,
                Evidence = $"Observed '{dhStr}' in proposal negotiation.",
                Recommendation = "Upgrade DH Group 5 to Group 14 (2048-bit) or Group 19 (256-bit ECP) to comply with current cryptographic standards."
            };
        }

        return null;
    }

    private static int ExtractGroupNumber(string dhStr)
    {
        var match = Regex.Match(dhStr, @"(?:Group\s*|group=?)(\d+)", RegexOptions.IgnoreCase);
        if (match.Success && int.TryParse(match.Groups[1].Value, out var val))
        {
            return val;
        }

        if (int.TryParse(dhStr.Trim(), out var directVal))
        {
            return directVal;
        }

        if (dhStr.Contains("768-bit", StringComparison.OrdinalIgnoreCase)) return 1;
        if (dhStr.Contains("1024-bit", StringComparison.OrdinalIgnoreCase)) return 2;
        if (dhStr.Contains("1536-bit", StringComparison.OrdinalIgnoreCase)) return 5;
        if (dhStr.Contains("2048-bit", StringComparison.OrdinalIgnoreCase)) return 14;
        if (dhStr.Contains("256-bit ECP", StringComparison.OrdinalIgnoreCase)) return 19;

        return 0;
    }
}
