using System.Text.RegularExpressions;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Rules;

/// <summary>
/// Evaluates Security Association key lifetimes against cryptographic exposure policies.
/// Flags excessively long lifetimes (e.g. > 24 hours / 86400s) that increase ciphertext volume under a single key.
/// </summary>
public class KeyLifetimeRule : ISecurityRule
{
    public string RuleId => "IPSEC-CONFIG-003";
    public SecurityRuleCategory Category => SecurityRuleCategory.KeyLifetime;
    public string Title => "Excessively Long Security Association Key Lifetime";
    public string Description => "The negotiated SA lifetime exceeds recommended operational limits. Extended key lifetimes increase the volume of ciphertext encrypted under the same symmetric key, expanding vulnerability windows for cryptanalysis and replay attacks.";

    public SecurityFinding? Evaluate(IpsecAnalysisResult analysis, SecurityPolicy policy)
    {
        var lifetimeStr = analysis.KeyLifetime;
        var proposalWithLifetime = analysis.SaProposals.FirstOrDefault(p => p.LifeDuration != "Default / Unspecified" && !string.IsNullOrWhiteSpace(p.LifeDuration));

        if (proposalWithLifetime != null)
        {
            lifetimeStr = proposalWithLifetime.LifeDuration;
        }

        if (string.IsNullOrWhiteSpace(lifetimeStr) ||
            lifetimeStr.Equals("Unknown", StringComparison.OrdinalIgnoreCase) ||
            lifetimeStr.Equals("Awaiting analysis", StringComparison.OrdinalIgnoreCase) ||
            lifetimeStr.Contains("Default", StringComparison.OrdinalIgnoreCase))
        {
            return null; // Not explicitly configured to excessive value or unobserved
        }

        long seconds = ParseLifetimeSeconds(lifetimeStr);
        if (seconds > policy.MaxAcceptableKeyLifetimeSeconds)
        {
            return new SecurityFinding
            {
                RuleId = RuleId,
                Category = Category,
                Title = Title,
                Description = Description,
                Severity = SeverityLevel.Medium,
                RiskContribution = policy.MediumWeight,
                ObservedValue = $"{lifetimeStr} ({seconds / 3600.0:F1} hours)",
                ExpectedValue = $"<= {policy.MaxRecommendedKeyLifetimeSeconds / 3600.0:F0} hours (<= {policy.MaxRecommendedKeyLifetimeSeconds:N0} seconds)",
                AffectedParameter = "IPsec SA Key Lifetime",
                Confidence = 1.0,
                AssessmentStatus = AssessmentStatus.Confirmed,
                Evidence = $"Observed SA lifetime configuration '{lifetimeStr}' in negotiated proposal attributes.",
                Recommendation = $"Reduce Phase 2 / IKE SA lifetime to {policy.MaxRecommendedKeyLifetimeSeconds / 3600.0:F0} hours (28,800 seconds) or 4,608,000 KB volume limit to enforce timely key rotation."
            };
        }

        return null;
    }

    private static long ParseLifetimeSeconds(string lifetimeStr)
    {
        var match = Regex.Match(lifetimeStr, @"(\d+)\s*(s|sec|seconds|m|min|minutes|h|hr|hours)?", RegexOptions.IgnoreCase);
        if (match.Success && long.TryParse(match.Groups[1].Value, out var num))
        {
            var unit = match.Groups[2].Value.ToLowerInvariant();
            if (unit.StartsWith("h")) return num * 3600;
            if (unit.StartsWith("m")) return num * 60;
            return num;
        }
        return 0;
    }
}
