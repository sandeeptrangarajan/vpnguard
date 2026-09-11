using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Rules;

/// <summary>
/// Evaluates ESP Anti-Replay protection and sequence number integrity.
/// Flags observed duplicate ESP sequence numbers or disabled replay window protection.
/// </summary>
public class ReplayProtectionRule : ISecurityRule
{
    public string RuleId => "IPSEC-CONFIG-002";
    public SecurityRuleCategory Category => SecurityRuleCategory.ReplayProtection;
    public string Title => "ESP Anti-Replay Protection Disabled or Packet Replays Detected";
    public string Description => "Anti-Replay protection verifies that each encrypted ESP packet carries a strictly unique and advancing sequence number within a sliding window. Duplicate sequence numbers indicate potential packet replay attacks, traffic loop injection, or disabled anti-replay checking.";

    public SecurityFinding? Evaluate(IpsecAnalysisResult analysis, SecurityPolicy policy)
    {
        if (!analysis.IsAnalyzed || analysis.EspPacketCount == 0)
        {
            return null; // Not assessable from capture
        }

        var replaySession = analysis.EspSessions.FirstOrDefault(s => s.DuplicateSequences > 0);
        bool replayDisabled = analysis.ReplayProtectionEnabled.HasValue && !analysis.ReplayProtectionEnabled.Value;

        if (replaySession != null || replayDisabled)
        {
            int dupCount = replaySession?.DuplicateSequences ?? 1;
            string spi = replaySession?.Spi ?? analysis.Spi ?? "ESP Session";

            return new SecurityFinding
            {
                RuleId = RuleId,
                Category = Category,
                Title = Title,
                Description = Description,
                Severity = SeverityLevel.High,
                RiskContribution = policy.HighWeight,
                ObservedValue = $"Duplicate Sequences Detected: {dupCount} duplicate(s) in SPI {spi}",
                ExpectedValue = "Strict In-Order Monotonic Sequence Progression (0 Replays)",
                AffectedParameter = "ESP Anti-Replay Sliding Window (RFC 4303)",
                Confidence = 1.0,
                AssessmentStatus = AssessmentStatus.Confirmed,
                Evidence = $"Observed {dupCount} duplicate sequence number(s) in ESP session (SPI: {spi}, Total Packets: {replaySession?.PacketCount ?? analysis.EspPacketCount ?? 0:N0}).",
                Recommendation = "Enable and enforce IPsec ESP Anti-Replay protection across all endpoints. Verify that QoS reordering windows (e.g. 64-bit or 128-bit ESN) are properly sized and not disabled."
            };
        }

        return null;
    }
}
