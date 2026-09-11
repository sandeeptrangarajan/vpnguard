using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;
using IPsecSecurityAnalyzer.Rules;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Real Security Assessment Engine (Phase 4).
/// Evaluates observed Phase 3 IPsec protocol parameters against modular security rules.
/// Computes deterministic risk scores, assessment coverage, and actionable recommendations.
/// Strictly adheres to the "No Fake Data" rule: unobserved parameters reduce coverage without false alerts.
/// </summary>
public class SecurityAssessmentService : ISecurityAssessmentService
{
    private readonly IIpsecAnalyzer _ipsecAnalyzer;
    private readonly IPcapAnalyzer _pcapAnalyzer;
    private readonly List<ISecurityRule> _rules;

    private SecurityPolicy _currentPolicy = new();
    private SecurityAssessment? _lastAssessment;

    public SecurityPolicy CurrentPolicy
    {
        get => _currentPolicy;
        set => _currentPolicy = value ?? new SecurityPolicy();
    }

    public SecurityAssessment? LastAssessment => _lastAssessment;

    public event EventHandler<SecurityAssessment?>? AssessmentCompleted;

    public SecurityAssessmentService(
        IIpsecAnalyzer ipsecAnalyzer,
        IPcapAnalyzer pcapAnalyzer,
        IEnumerable<ISecurityRule>? rules = null)
    {
        _ipsecAnalyzer = ipsecAnalyzer;
        _pcapAnalyzer = pcapAnalyzer;

        // Initialize rule set
        if (rules != null && rules.Any())
        {
            _rules = rules.ToList();
        }
        else
        {
            _rules = new List<ISecurityRule>
            {
                new IkeVersionRule(),
                new AggressiveModeRule(),
                new EncryptionAlgorithmRule(),
                new IntegrityAlgorithmRule(),
                new DiffieHellmanGroupRule(),
                new PfsRule(),
                new ReplayProtectionRule(),
                new KeyLifetimeRule(),
                new SaConsistencyRule(),
                new UnknownParameterRule()
            };
        }

        // Automatically trigger security assessment upon PCAP analysis completion
        _pcapAnalyzer.AnalysisCompleted += async (s, e) =>
        {
            if (e != null)
            {
                await AssessAsync();
            }
            else
            {
                _lastAssessment = null;
                AssessmentCompleted?.Invoke(this, null);
            }
        };
    }

    public async Task<SecurityAssessment> AssessAsync(IpsecAnalysisResult? analysis = null, SecurityPolicy? customPolicy = null)
    {
        var policy = customPolicy ?? _currentPolicy;

        // If no explicit result provided, fetch the latest from IpsecAnalyzer
        if (analysis == null)
        {
            analysis = await _ipsecAnalyzer.GetIpsecAnalysisAsync();
        }

        // Case 1: Unanalyzed state (No Fake Data baseline)
        if (analysis == null || !analysis.IsAnalyzed)
        {
            var unanalyzed = new SecurityAssessment
            {
                OverallRiskScore = null,
                RiskLevel = RiskLevel.Unknown,
                Findings = new List<SecurityFinding>(),
                Recommendations = new List<SecurityRecommendation>(),
                Summary = "No assessment available. Load and analyze a PCAP file to perform security assessment.",
                AssessmentTimestamp = null,
                AssessedParameterCount = 0,
                UnknownParameterCount = 8,
                AssessmentCoverage = 0.0
            };
            _lastAssessment = unanalyzed;
            AssessmentCompleted?.Invoke(this, unanalyzed);
            return unanalyzed;
        }

        // Case 2: Analysis performed - run all modular rules
        var rawFindings = new List<SecurityFinding>();
        foreach (var rule in _rules)
        {
            try
            {
                var finding = rule.Evaluate(analysis, policy);
                if (finding != null)
                {
                    rawFindings.Add(finding);
                }
            }
            catch (Exception ex)
            {
                // Capture rule execution exception without halting assessment
                rawFindings.Add(new SecurityFinding
                {
                    RuleId = rule.RuleId,
                    Category = rule.Category,
                    Title = $"Rule Evaluation Notice ({rule.Title})",
                    Description = $"Rule evaluation encountered an unexpected condition: {ex.Message}",
                    Severity = SeverityLevel.Informational,
                    RiskContribution = 0.0,
                    AssessmentStatus = AssessmentStatus.NotAssessable,
                    Evidence = "Internal rule engine observation.",
                    Recommendation = "Check capture integrity or update rule policy configuration."
                });
            }
        }

        // Deduplicate findings by RuleId and ObservedValue so repeated packet frames do not inflate risk score
        var deduplicatedFindings = new List<SecurityFinding>();
        var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var finding in rawFindings)
        {
            string key = $"{finding.RuleId}_{finding.ObservedValue}_{finding.Severity}";
            if (seenKeys.Add(key))
            {
                deduplicatedFindings.Add(finding);
            }
        }

        // Sort findings: Critical -> High -> Medium -> Low -> Informational
        deduplicatedFindings = deduplicatedFindings
            .OrderByDescending(f => (int)f.Severity)
            .ThenByDescending(f => f.RiskContribution)
            .ToList();

        // Calculate Parameter Assessment Coverage
        int totalCoreParameters = 8;
        int assessedCount = 0;

        if (!string.IsNullOrWhiteSpace(analysis.IkevVersion) && !analysis.IkevVersion.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            assessedCount++;
        if (!string.IsNullOrWhiteSpace(analysis.ExchangeType) && !analysis.ExchangeType.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            assessedCount++;
        if (!string.IsNullOrWhiteSpace(analysis.EncryptionAlgorithm) && !analysis.EncryptionAlgorithm.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            assessedCount++;
        if (!string.IsNullOrWhiteSpace(analysis.IntegrityAlgorithm) && !analysis.IntegrityAlgorithm.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            assessedCount++;
        if (!string.IsNullOrWhiteSpace(analysis.DhGroup) && !analysis.DhGroup.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            assessedCount++;
        if (analysis.PfsEnabled.HasValue)
            assessedCount++;
        if (analysis.ReplayProtectionEnabled.HasValue || analysis.EspSessions.Count > 0)
            assessedCount++;
        if (!string.IsNullOrWhiteSpace(analysis.KeyLifetime) && !analysis.KeyLifetime.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
            assessedCount++;

        int unknownCount = Math.Max(0, totalCoreParameters - assessedCount);
        double coveragePercentage = Math.Round((double)assessedCount / totalCoreParameters * 100.0, 1);

        // Deterministic Risk Score Calculation
        // Sum the contributions of all actionable findings (excluding Informational)
        double rawRiskScore = deduplicatedFindings
            .Where(f => f.Severity != SeverityLevel.Informational)
            .Sum(f => f.RiskContribution);

        // Normalize raw score to a transparent 0–100 scale based on policy scale factor
        double calculatedScore = Math.Min(100.0, Math.Round((rawRiskScore / policy.MaxExpectedRawScore) * 100.0, 0));

        // If no security vulnerabilities exist and we observed valid traffic, score is 0 / 100 (Clean)
        if (deduplicatedFindings.All(f => f.Severity == SeverityLevel.Informational))
        {
            calculatedScore = 0.0;
        }

        // Map calculated score to Risk Level classification band
        RiskLevel riskLevel;
        if (calculatedScore <= policy.LowThresholdMax)
            riskLevel = RiskLevel.Low;
        else if (calculatedScore <= policy.ModerateThresholdMax)
            riskLevel = RiskLevel.Moderate;
        else if (calculatedScore <= policy.ElevatedThresholdMax)
            riskLevel = RiskLevel.Elevated;
        else if (calculatedScore <= policy.HighThresholdMax)
            riskLevel = RiskLevel.High;
        else
            riskLevel = RiskLevel.Critical;

        // Generate Actionable Recommendations mapped directly from findings
        var recommendations = new List<SecurityRecommendation>();
        foreach (var finding in deduplicatedFindings.Where(f => !string.IsNullOrWhiteSpace(f.Recommendation) && f.Severity != SeverityLevel.Informational))
        {
            recommendations.Add(new SecurityRecommendation
            {
                Title = $"Remediate: {finding.Title}",
                Priority = finding.Severity,
                RecommendationText = finding.Recommendation,
                Reason = finding.Description,
                RelatedFindingId = finding.FindingId,
                ObservedEvidence = finding.Evidence,
                AffectedParameter = finding.AffectedParameter
            });
        }

        // Compose Summary Text
        string summaryText;
        if (deduplicatedFindings.Count == 0 || deduplicatedFindings.All(f => f.Severity == SeverityLevel.Informational))
        {
            summaryText = $"Compliant Configuration: No security vulnerabilities or weak cryptographic transforms detected across {assessedCount} assessed parameter(s) (Coverage: {coveragePercentage:F0}%).";
        }
        else
        {
            int actionableCount = deduplicatedFindings.Count(f => f.Severity != SeverityLevel.Informational);
            summaryText = $"Security Assessment identified {actionableCount} finding(s) ({deduplicatedFindings.Count(f => f.Severity == SeverityLevel.Critical)} Critical, {deduplicatedFindings.Count(f => f.Severity == SeverityLevel.High)} High, {deduplicatedFindings.Count(f => f.Severity == SeverityLevel.Medium)} Medium) with an overall Risk Score of {calculatedScore:F0}/100 ({riskLevel}).";
        }

        // Construct complete assessment result
        var assessment = new SecurityAssessment
        {
            OverallRiskScore = calculatedScore,
            RiskLevel = riskLevel,
            Findings = deduplicatedFindings,
            Recommendations = recommendations,
            AssessedParameterCount = assessedCount,
            UnknownParameterCount = unknownCount,
            AssessmentCoverage = coveragePercentage,
            AssessmentTimestamp = DateTime.Now,
            PolicyName = policy.PolicyName,
            PolicyVersion = policy.PolicyVersion,
            Summary = summaryText,
            Warnings = deduplicatedFindings
                .Where(f => f.Severity >= SeverityLevel.High)
                .Select(f => f.Title)
                .ToList(),

            // Status indicators for UI
            CryptographicStrengthStatus = deduplicatedFindings.Any(f => f.Category == SecurityRuleCategory.Encryption || f.Category == SecurityRuleCategory.Integrity)
                ? "Weaknesses Detected" : (assessedCount > 0 ? "Strong / Compliant" : "Not observed"),
            ProtocolSecurityStatus = deduplicatedFindings.Any(f => f.Category == SecurityRuleCategory.IkeVersion)
                ? "Legacy Version" : (assessedCount > 0 ? "Modern (IKEv2)" : "Not observed"),
            KeyExchangeSecurityStatus = deduplicatedFindings.Any(f => f.Category == SecurityRuleCategory.DiffieHellman)
                ? "Sub-2048 bit MODP" : (assessedCount > 0 ? "NIST Compliant" : "Not observed"),
            PfsStatus = analysis.PfsEnabled.HasValue ? (analysis.PfsEnabled.Value ? "Enabled / Verified" : "Disabled") : "Not observed",
            ReplayProtectionStatus = deduplicatedFindings.Any(f => f.Category == SecurityRuleCategory.ReplayProtection)
                ? "Anomalies / Replays" : (analysis.EspSessions.Count > 0 ? "Active / In-Order" : "Not observed"),
            SaConfigurationStatus = deduplicatedFindings.Any(f => f.Category == SecurityRuleCategory.SecurityAssociation || f.Category == SecurityRuleCategory.KeyLifetime)
                ? "Deviations Observed" : (assessedCount > 0 ? "Consistent" : "Not observed")
        };

        _lastAssessment = assessment;
        AssessmentCompleted?.Invoke(this, assessment);

        return assessment;
    }

    public Task<SecurityAssessment> GetSecurityAssessmentAsync()
    {
        if (_lastAssessment != null)
        {
            return Task.FromResult(_lastAssessment);
        }

        return AssessAsync();
    }

    public Task<IReadOnlyList<SecurityFinding>> GetFindingsAsync()
    {
        if (_lastAssessment != null)
        {
            return Task.FromResult<IReadOnlyList<SecurityFinding>>(_lastAssessment.Findings);
        }

        return Task.FromResult<IReadOnlyList<SecurityFinding>>(new List<SecurityFinding>());
    }

    public Task<IReadOnlyList<SecurityRecommendation>> GetRecommendationsAsync()
    {
        if (_lastAssessment != null)
        {
            return Task.FromResult<IReadOnlyList<SecurityRecommendation>>(_lastAssessment.Recommendations);
        }

        return Task.FromResult<IReadOnlyList<SecurityRecommendation>>(new List<SecurityRecommendation>());
    }
}
