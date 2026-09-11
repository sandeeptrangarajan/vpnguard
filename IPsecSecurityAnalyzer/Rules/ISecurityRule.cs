using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Rules;

/// <summary>
/// Modular contract for an independent, deterministic security evaluation rule.
/// </summary>
public interface ISecurityRule
{
    string RuleId { get; }
    SecurityRuleCategory Category { get; }
    string Title { get; }
    string Description { get; }

    /// <summary>
    /// Evaluates the observed IPsec analysis result against the configured security policy.
    /// Returns a SecurityFinding if an issue or observation is identified; otherwise null.
    /// </summary>
    SecurityFinding? Evaluate(IpsecAnalysisResult analysis, SecurityPolicy policy);
}
