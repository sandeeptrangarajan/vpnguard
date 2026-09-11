using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;
using IPsecSecurityAnalyzer.Rules;
using IPsecSecurityAnalyzer.Services;
using IPsecSecurityAnalyzer.ViewModels;

namespace IPsecSecurityAnalyzer.Tests;

public class MockTsharkService : ITsharkService
{
    public bool IsAvailable { get; set; } = true;
    public string DetectedPath { get; set; } = @"C:\Program Files\Wireshark\tshark.exe";
    public string MockStdout { get; set; } = string.Empty;
    public string MockStderr { get; set; } = string.Empty;
    public int ExitCode { get; set; } = 0;
    public bool SimulateTimeout { get; set; } = false;
    public bool SimulateCancel { get; set; } = false;

    public bool IsTsharkAvailable(string? customPath = null) => IsAvailable;
    public string? FindTsharkPath(string? customPath = null) => IsAvailable ? (customPath ?? DetectedPath) : null;

    public Task<string?> GetTsharkVersionAsync(string? customPath = null, CancellationToken cancellationToken = default)
    {
        if (!IsAvailable)
        {
            return Task.FromResult<string?>(null);
        }
        return Task.FromResult<string?>("TShark (Wireshark) 4.2.0 (v4.2.0-0-g54000)");
    }

    public Task<TsharkExecutionResult> ExecuteAsync(
        IEnumerable<string> arguments,
        string? customPath = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        if (SimulateCancel || cancellationToken.IsCancellationRequested)
        {
            return Task.FromResult(new TsharkExecutionResult { IsCancelled = true });
        }

        if (SimulateTimeout)
        {
            return Task.FromResult(new TsharkExecutionResult { IsTimeout = true });
        }

        return Task.FromResult(new TsharkExecutionResult
        {
            ExitCode = ExitCode,
            StandardOutput = MockStdout,
            StandardError = MockStderr
        });
    }
}

public class Program
{
    [STAThread]
    public static async Task<int> Main(string[] args)
    {
        Console.WriteLine("================================================================================");
        Console.WriteLine("   IPsec Security Analyzer - Phase 4 Security Assessment Engine Test Suite");
        Console.WriteLine("================================================================================");

        int passed = 0;
        int failed = 0;

        void Assert(bool condition, string testName, string? details = null)
        {
            if (condition)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("[PASS] ");
                Console.ResetColor();
                Console.WriteLine(testName);
                if (!string.IsNullOrEmpty(details))
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"       └─ {details}");
                    Console.ResetColor();
                }
                passed++;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("[FAIL] ");
                Console.ResetColor();
                Console.WriteLine(testName);
                if (!string.IsNullOrEmpty(details))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"       └─ Failure detail: {details}");
                    Console.ResetColor();
                }
                failed++;
            }
        }

        // -------------------------------------------------------------
        // SECTION A: Architecture & Backwards Compatibility (Phases 1-3)
        // -------------------------------------------------------------
        Console.WriteLine("\n[SECTION A] Architecture & Backwards Compatibility");

        var services = new ServiceCollection();
        services.AddSingleton<INavigationService, NavigationService>();
        services.AddSingleton<ITsharkService, MockTsharkService>();
        services.AddSingleton<IPcapAnalyzer, PcapAnalyzer>();
        services.AddSingleton<ILiveCaptureService, LiveCaptureService>();
        services.AddSingleton<IIpsecAnalyzer, IpsecAnalyzer>();
        services.AddSingleton<ISecurityAssessmentService, SecurityAssessmentService>();
        services.AddSingleton<IAiAnalysisService, AiAnalysisService>();
        services.AddSingleton<IReportService, ReportService>();
        services.AddSingleton<IAnalysisHistoryService, AnalysisHistoryService>();
        services.AddSingleton<IFileDialogService, FileDialogService>();
        services.AddSingleton<ISettingsService, SettingsService>();

        services.AddSingleton<DashboardViewModel>();
        services.AddSingleton<PcapAnalysisViewModel>();
        services.AddSingleton<LiveCaptureViewModel>();
        services.AddSingleton<IpsecAnalysisViewModel>();
        services.AddSingleton<AiAnalysisViewModel>();
        services.AddSingleton<SecurityAssessmentViewModel>();
        services.AddSingleton<FindingsViewModel>();
        services.AddSingleton<RecommendationsViewModel>();
        services.AddSingleton<ReportsViewModel>();
        services.AddSingleton<HistoryViewModel>();
        services.AddSingleton<SettingsViewModel>();
        services.AddSingleton<MainViewModel>();

        var provider = services.BuildServiceProvider();
        var mainVm = provider.GetRequiredService<MainViewModel>();
        var navService = provider.GetRequiredService<INavigationService>();

        Assert(mainVm != null, "DI container resolves MainViewModel cleanly with all 11 ViewModels");
        Assert(provider.GetRequiredService<ISecurityAssessmentService>() != null, "ISecurityAssessmentService resolved from DI");

        bool navSuccess = true;
        foreach (NavigationPage page in Enum.GetValues<NavigationPage>())
        {
            navService.NavigateTo(page);
            if (mainVm?.CurrentPage != page || string.IsNullOrWhiteSpace(mainVm?.CurrentPageTitle))
            {
                navSuccess = false;
            }
        }
        Assert(navSuccess, "Navigation across all 11 pages remains functional");

        var assessmentService = provider.GetRequiredService<ISecurityAssessmentService>();
        var initialAssessment = await assessmentService.GetSecurityAssessmentAsync();
        Assert(initialAssessment.OverallRiskScore == null && initialAssessment.RiskLevel == RiskLevel.Unknown,
               "No Fake Data: Security Assessment initial unanalyzed state has null score and Unknown risk level");

        // -------------------------------------------------------------
        // SECTION B: Phase 4 Modular Rules & Scenarios (24 Required Tests)
        // -------------------------------------------------------------
        Console.WriteLine("\n[SECTION B] Phase 4 Security Rules & Assessment Scenarios");

        var policy = new SecurityPolicy();

        // SCENARIO 1: Strong IKEv2 Configuration (Compliant Baseline)
        var strongIkev2Result = new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            IkevVersion = "IKEv2",
            ExchangeType = "IKE_SA_INIT (34)",
            EncryptionAlgorithm = "AES-256-GCM",
            IntegrityAlgorithm = "None (AEAD Combined)",
            DhGroup = "Group 19 (256-bit ECP - Strong)",
            PfsEnabled = true,
            ReplayProtectionEnabled = true,
            KeyLifetime = "28800 seconds (8 hours)",
            IkePacketCount = 10,
            EspPacketCount = 500,
            EspSessions = new List<EspSessionInfo>
            {
                new EspSessionInfo { Spi = "0x1a2b3c4d", FirstSequence = 1, LastSequence = 500, DuplicateSequences = 0, SequenceGaps = 0, PacketCount = 500 }
            }
        };
        var assessStrong = await assessmentService.AssessAsync(strongIkev2Result, policy);
        Assert(assessStrong.OverallRiskScore == 0.0 && assessStrong.RiskLevel == RiskLevel.Low && assessStrong.Findings.Count(f => f.Severity != SeverityLevel.Informational) == 0,
               "Scenario 1: Strong IKEv2 configuration produces 0.0 Risk Score and Low Risk Level",
               $"Score: {assessStrong.OverallRiskScore}/100, Level: {assessStrong.RiskLevel}, Actionable Findings: {assessStrong.Findings.Count(f => f.Severity != SeverityLevel.Informational)}");

        // SCENARIO 2: IKEv1 Detection (Medium Severity)
        var ikev1Result = new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            IkevVersion = "IKEv1",
            ExchangeType = "Main Mode (2)",
            EncryptionAlgorithm = "AES-256-CBC",
            IntegrityAlgorithm = "HMAC-SHA256-128",
            DhGroup = "Group 14 (2048-bit MODP)",
            PfsEnabled = true,
            ReplayProtectionEnabled = true,
            IkePacketCount = 6
        };
        var assessIkev1 = await assessmentService.AssessAsync(ikev1Result, policy);
        var ikev1Finding = assessIkev1.Findings.FirstOrDefault(f => f.RuleId == "IPSEC-IKE-001");
        Assert(ikev1Finding != null && ikev1Finding.Severity == SeverityLevel.Medium && ikev1Finding.RiskContribution == 4.0,
               "Scenario 2: IKEv1 detection flags IPSEC-IKE-001 with Medium Severity",
               $"RuleId: {ikev1Finding?.RuleId}, Severity: {ikev1Finding?.Severity}, Weight: {ikev1Finding?.RiskContribution}");

        // SCENARIO 3: Weak Encryption (3DES / DES -> High, NULL -> Critical)
        var weak3desResult = new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            IkevVersion = "IKEv2",
            EncryptionAlgorithm = "3DES-CBC",
            IntegrityAlgorithm = "HMAC-SHA256-128",
            DhGroup = "Group 14 (2048-bit MODP)",
            PfsEnabled = true,
            ReplayProtectionEnabled = true,
            IkePacketCount = 4
        };
        var assess3des = await assessmentService.AssessAsync(weak3desResult, policy);
        var enc3desFinding = assess3des.Findings.FirstOrDefault(f => f.RuleId == "IPSEC-CRYPTO-001");
        Assert(enc3desFinding != null && enc3desFinding.Severity == SeverityLevel.High && enc3desFinding.Description.Contains("Sweet32"),
               "Scenario 3a: Weak 3DES-CBC encryption flagged as High Severity with Sweet32 explanation",
               $"RuleId: {enc3desFinding?.RuleId}, Severity: {enc3desFinding?.Severity}");

        var nullEncResult = new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            IkevVersion = "IKEv2",
            EncryptionAlgorithm = "NULL",
            IntegrityAlgorithm = "HMAC-SHA256-128",
            DhGroup = "Group 14 (2048-bit MODP)",
            PfsEnabled = true,
            ReplayProtectionEnabled = true,
            IkePacketCount = 2
        };
        var assessNull = await assessmentService.AssessAsync(nullEncResult, policy);
        var nullFinding = assessNull.Findings.FirstOrDefault(f => f.RuleId == "IPSEC-CRYPTO-001");
        Assert(nullFinding != null && nullFinding.Severity == SeverityLevel.Critical,
               "Scenario 3b: NULL encryption transform flagged as Critical Severity (Unencrypted)",
               $"Severity: {nullFinding?.Severity}, Title: {nullFinding?.Title}");

        // SCENARIO 4: Strong Encryption (AES-GCM / AES-256)
        var strongEncRule = new EncryptionAlgorithmRule();
        var strongEncFinding = strongEncRule.Evaluate(strongIkev2Result, policy);
        Assert(strongEncFinding == null, "Scenario 4: Strong AES-256-GCM encryption produces zero vulnerability findings");

        // SCENARIO 5: Weak Integrity (MD5 / HMAC-MD5 -> High)
        var weakMd5Result = new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            IkevVersion = "IKEv2",
            EncryptionAlgorithm = "AES-256-CBC",
            IntegrityAlgorithm = "HMAC-MD5-96",
            DhGroup = "Group 14 (2048-bit MODP)",
            PfsEnabled = true,
            ReplayProtectionEnabled = true,
            IkePacketCount = 2
        };
        var assessMd5 = await assessmentService.AssessAsync(weakMd5Result, policy);
        var md5Finding = assessMd5.Findings.FirstOrDefault(f => f.RuleId == "IPSEC-CRYPTO-002");
        Assert(md5Finding != null && md5Finding.Severity == SeverityLevel.High && md5Finding.Description.Contains("collision"),
               "Scenario 5: Deprecated HMAC-MD5 integrity flagged as High Severity with collision warning",
               $"RuleId: {md5Finding?.RuleId}, Severity: {md5Finding?.Severity}");

        // SCENARIO 6: Strong Integrity (HMAC-SHA256 / SHA512)
        var strongIntegRule = new IntegrityAlgorithmRule();
        var strongIntegFinding = strongIntegRule.Evaluate(new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            IntegrityAlgorithm = "HMAC-SHA512-256"
        }, policy);
        Assert(strongIntegFinding == null, "Scenario 6: Modern HMAC-SHA512 integrity produces zero vulnerability findings");

        // SCENARIO 7: Weak DH Group (Group 2: 1024-bit -> High)
        var weakDhResult = new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            IkevVersion = "IKEv2",
            EncryptionAlgorithm = "AES-256-CBC",
            IntegrityAlgorithm = "HMAC-SHA256-128",
            DhGroup = "Group 2 (1024-bit MODP)",
            PfsEnabled = true,
            ReplayProtectionEnabled = true,
            IkePacketCount = 4
        };
        var assessDh = await assessmentService.AssessAsync(weakDhResult, policy);
        var dhFinding = assessDh.Findings.FirstOrDefault(f => f.RuleId == "IPSEC-CRYPTO-003");
        Assert(dhFinding != null && dhFinding.Severity == SeverityLevel.High && dhFinding.Description.Contains("2048 bits"),
               "Scenario 7: Weak Diffie-Hellman Group 2 (1024-bit) flagged as High Severity with modulus warning",
               $"RuleId: {dhFinding?.RuleId}, Severity: {dhFinding?.Severity}");

        // SCENARIO 8: Strong DH Group (Group 14: 2048-bit, Group 19: 256-bit ECP)
        var dhRule = new DiffieHellmanGroupRule();
        var strongDhFinding = dhRule.Evaluate(new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            DhGroup = "Group 19 (256-bit Random ECP)"
        }, policy);
        Assert(strongDhFinding == null, "Scenario 8: Strong DH Group 19 (ECP) produces zero vulnerability findings");

        // SCENARIO 9: PFS Disabled (Medium Severity)
        var noPfsResult = new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            IkevVersion = "IKEv2",
            EncryptionAlgorithm = "AES-256-GCM",
            IntegrityAlgorithm = "None (AEAD Combined)",
            DhGroup = "Group 14",
            PfsEnabled = false,
            ReplayProtectionEnabled = true,
            IkePacketCount = 4,
            EspPacketCount = 100
        };
        var assessNoPfs = await assessmentService.AssessAsync(noPfsResult, policy);
        var pfsFinding = assessNoPfs.Findings.FirstOrDefault(f => f.RuleId == "IPSEC-CONFIG-001");
        Assert(pfsFinding != null && pfsFinding.Severity == SeverityLevel.Medium && pfsFinding.Description.Contains("retrospective decryption"),
               "Scenario 9: Disabled Perfect Forward Secrecy (PFS) flagged as Medium Severity",
               $"RuleId: {pfsFinding?.RuleId}, Severity: {pfsFinding?.Severity}");

        // SCENARIO 10: PFS Enabled (Clean)
        var pfsRule = new PfsRule();
        var pfsFindingOk = pfsRule.Evaluate(new IpsecAnalysisResult { IsAnalyzed = true, PfsEnabled = true, IkePacketCount = 5 }, policy);
        Assert(pfsFindingOk == null, "Scenario 10: Enabled PFS produces zero vulnerability findings");

        // SCENARIO 11: Replay Protection Disabled / Duplicates Detected (High Severity)
        var replayAttackResult = new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            IkevVersion = "IKEv2",
            EncryptionAlgorithm = "AES-256-GCM",
            IntegrityAlgorithm = "None (AEAD Combined)",
            DhGroup = "Group 14",
            PfsEnabled = true,
            ReplayProtectionEnabled = false,
            EspPacketCount = 200,
            EspSessions = new List<EspSessionInfo>
            {
                new EspSessionInfo { Spi = "0xdeadbeef", DuplicateSequences = 4, SequenceGaps = 2, PacketCount = 200 }
            }
        };
        var assessReplay = await assessmentService.AssessAsync(replayAttackResult, policy);
        var replayFinding = assessReplay.Findings.FirstOrDefault(f => f.RuleId == "IPSEC-CONFIG-002");
        Assert(replayFinding != null && replayFinding.Severity == SeverityLevel.High && replayFinding.Evidence.Contains("4 duplicate"),
               "Scenario 11: Replay protection disabled / duplicate sequences flagged as High Severity",
               $"RuleId: {replayFinding?.RuleId}, Evidence: {replayFinding?.Evidence}");

        // SCENARIO 12: Replay Protection Enabled (Clean)
        var replayRule = new ReplayProtectionRule();
        var replayFindingOk = replayRule.Evaluate(strongIkev2Result, policy);
        Assert(replayFindingOk == null, "Scenario 12: Active Anti-Replay with monotonic sequences produces zero findings");

        // SCENARIO 13: Long Key Lifetime (> 24 hours / 86400s -> Medium Severity)
        var longLifetimeResult = new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            IkevVersion = "IKEv2",
            KeyLifetime = "172800 seconds (48 hours)",
            IkePacketCount = 2
        };
        var lifetimeRule = new KeyLifetimeRule();
        var lifetimeFinding = lifetimeRule.Evaluate(longLifetimeResult, policy);
        Assert(lifetimeFinding != null && lifetimeFinding.Severity == SeverityLevel.Medium && lifetimeFinding.ObservedValue.Contains("48"),
               "Scenario 13: Excessively long SA lifetime (48 hours) flagged as Medium Severity",
               $"RuleId: {lifetimeFinding?.RuleId}, Observed: {lifetimeFinding?.ObservedValue}");

        // SCENARIO 14: Unknown Parameters Handling (Coverage reduction, NO false positive vulnerabilities)
        var unknownParamsResult = new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            IkevVersion = "Unknown",
            ExchangeType = "Unknown",
            EncryptionAlgorithm = "Unknown",
            IntegrityAlgorithm = "Unknown",
            DhGroup = "Unknown",
            PfsEnabled = null,
            ReplayProtectionEnabled = null,
            KeyLifetime = "Unknown",
            IkePacketCount = 2,
            EspPacketCount = 10
        };
        var assessUnknown = await assessmentService.AssessAsync(unknownParamsResult, policy);
        var actionableUnknowns = assessUnknown.Findings.Where(f => f.Severity != SeverityLevel.Informational).ToList();
        Assert(actionableUnknowns.Count == 0 && assessUnknown.OverallRiskScore == 0.0 && assessUnknown.AssessmentCoverage == 0.0,
               "Scenario 14: Unknown parameters do NOT generate false vulnerabilities and report 0% coverage",
               $"Actionable Findings: {actionableUnknowns.Count}, Risk Score: {assessUnknown.OverallRiskScore}, Coverage: {assessUnknown.AssessmentCoverage}%");

        // SCENARIO 15: Mixed Findings & Multi-Vulnerability Assessment
        var mixedVulnerabilities = new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            IkevVersion = "IKEv1",
            ExchangeType = "Aggressive Mode (4)",
            AggressiveModeDetected = true,
            EncryptionAlgorithm = "3DES-CBC",
            IntegrityAlgorithm = "HMAC-MD5",
            DhGroup = "Group 2 (1024-bit MODP)",
            PfsEnabled = false,
            ReplayProtectionEnabled = true,
            KeyLifetime = "28800 seconds",
            IkePacketCount = 12,
            EspPacketCount = 80
        };
        var assessMixed = await assessmentService.AssessAsync(mixedVulnerabilities, policy);
        Assert(assessMixed.Findings.Count >= 5 && assessMixed.CriticalCount == 0 && assessMixed.HighCount >= 3 && assessMixed.MediumCount >= 2,
               "Scenario 15: Mixed findings correctly evaluated with categorized severities",
               $"Total: {assessMixed.TotalFindingsCount}, High: {assessMixed.HighCount}, Medium: {assessMixed.MediumCount}");

        // SCENARIO 16: Multiple Findings with Varying Severities
        Assert(assessMixed.Findings.Any(f => f.Severity == SeverityLevel.High) &&
               assessMixed.Findings.Any(f => f.Severity == SeverityLevel.Medium),
               "Scenario 16: Multiple findings span distinct severity classifications (High, Medium)");

        // SCENARIO 17: Duplicate Finding Prevention (Deduplication)
        // Simulate analysis result with multiple redundant proposals containing same weak cipher
        var dupProposalResult = new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            IkevVersion = "IKEv2",
            EncryptionAlgorithm = "3DES-CBC",
            SaProposals = new List<IkeSaProposal>
            {
                new IkeSaProposal { ProposalNumber = 1, EncryptionAlgorithm = "3DES-CBC", IntegrityAlgorithm = "HMAC-SHA256-128", DhGroup = "Group 14" },
                new IkeSaProposal { ProposalNumber = 2, EncryptionAlgorithm = "3DES-CBC", IntegrityAlgorithm = "HMAC-SHA256-128", DhGroup = "Group 14" },
                new IkeSaProposal { ProposalNumber = 3, EncryptionAlgorithm = "3DES-CBC", IntegrityAlgorithm = "HMAC-SHA256-128", DhGroup = "Group 14" }
            },
            IkePacketCount = 6
        };
        var assessDeduplicated = await assessmentService.AssessAsync(dupProposalResult, policy);
        int encCount = assessDeduplicated.Findings.Count(f => f.RuleId == "IPSEC-CRYPTO-001");
        Assert(encCount == 1,
               "Scenario 17: Duplicate finding prevention deduplicates 3 identical 3DES proposals into 1 finding",
               $"Finding count for IPSEC-CRYPTO-001: {encCount}");

        // SCENARIO 18: Deterministic Risk Score Calculation
        // mixedVulnerabilities has: IKEv1 (4.0) + Aggressive (7.0) + 3DES (7.0) + MD5 (7.0) + DH2 (7.0) + NoPFS (4.0) = Raw 36.0 -> Normalized: min(100, 36/30 * 100) = 100.0 (Critical)
        Assert(assessMixed.OverallRiskScore.HasValue && assessMixed.OverallRiskScore.Value == 100.0,
               "Scenario 18: Deterministic risk score computed mathematically from weights (Normalized Score = 100)",
               $"Calculated Score: {assessMixed.OverallRiskScore}");

        // Single finding risk score check: IKEv1 (4.0) -> (4.0 / 30.0) * 100 = 13.3 -> rounded = 13
        Assert(assessIkev1.OverallRiskScore.HasValue && Math.Abs(assessIkev1.OverallRiskScore.Value - 13.0) <= 1.0,
               "Scenario 18b: Single Medium finding produces deterministic score of 13 / 100",
               $"Calculated Score: {assessIkev1.OverallRiskScore}");

        // SCENARIO 19: Risk Level Classification Bands
        Assert(assessStrong.RiskLevel == RiskLevel.Low, "Scenario 19a: Score 0 maps to Low Risk Level");
        Assert(assessIkev1.RiskLevel == RiskLevel.Low, "Scenario 19b: Score 13 maps to Low Risk Level (0-19 band)");
        Assert(assessMixed.RiskLevel == RiskLevel.Critical, "Scenario 19c: Score 100 maps to Critical Risk Level (80-100 band)");

        // SCENARIO 20: Assessment Coverage Calculation
        // strongIkev2Result has 8 of 8 parameters known -> 100.0%
        Assert(assessStrong.AssessedParameterCount == 8 && assessStrong.AssessmentCoverage == 100.0,
               "Scenario 20a: Full parameter observation yields 100% Assessment Coverage",
               $"Assessed: {assessStrong.AssessedParameterCount}/8, Coverage: {assessStrong.AssessmentCoverage}%");

        // Partial result with 4 known parameters
        var partialResult = new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            IkevVersion = "IKEv2",
            ExchangeType = "IKE_SA_INIT",
            EncryptionAlgorithm = "AES-256-GCM",
            IntegrityAlgorithm = "None (AEAD)",
            DhGroup = "Unknown",
            PfsEnabled = null,
            ReplayProtectionEnabled = null,
            KeyLifetime = "Unknown",
            IkePacketCount = 2
        };
        var assessPartial = await assessmentService.AssessAsync(partialResult, policy);
        Assert(assessPartial.AssessedParameterCount == 4 && assessPartial.UnknownParameterCount == 4 && assessPartial.AssessmentCoverage == 50.0,
               "Scenario 20b: Partial observation (4 of 8 parameters) yields 50% Assessment Coverage",
               $"Assessed: {assessPartial.AssessedParameterCount}, Unknown: {assessPartial.UnknownParameterCount}, Coverage: {assessPartial.AssessmentCoverage}%");

        // SCENARIO 21: No-IPsec Capture Analysis (No fake vulnerabilities)
        var noIpsecResult = new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            Protocol = "None",
            TrafficType = "No IPsec traffic detected",
            IkePacketCount = 0,
            EspPacketCount = 0,
            AhPacketCount = 0
        };
        var assessNoIpsec = await assessmentService.AssessAsync(noIpsecResult, policy);
        Assert(assessNoIpsec.Findings.Count(f => f.Severity != SeverityLevel.Informational) == 0 && assessNoIpsec.OverallRiskScore == 0.0,
               "Scenario 21: Capture with no IPsec traffic produces 0 vulnerability findings",
               $"Actionable Findings: {assessNoIpsec.Findings.Count(f => f.Severity != SeverityLevel.Informational)}");

        // SCENARIO 22: Empty Analysis Result Handling
        var emptyResult = new IpsecAnalysisResult { IsAnalyzed = false };
        var assessEmpty = await assessmentService.AssessAsync(emptyResult, policy);
        Assert(assessEmpty.OverallRiskScore == null && assessEmpty.RiskLevel == RiskLevel.Unknown,
               "Scenario 22: Empty unanalyzed result handled gracefully with null score");

        // SCENARIO 23: Missing Fields & Null Safety Handling
        var nullFieldsResult = new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            IkevVersion = null,
            ExchangeType = null,
            EncryptionAlgorithm = null,
            IntegrityAlgorithm = null,
            DhGroup = null,
            KeyLifetime = null,
            IkePacketCount = null,
            EspPacketCount = null
        };
        var assessNullFields = await assessmentService.AssessAsync(nullFieldsResult, policy);
        Assert(assessNullFields != null && assessNullFields.Findings.Count(f => f.Severity != SeverityLevel.Informational) == 0,
               "Scenario 23: Null properties handled safely without NullReferenceException");

        // SCENARIO 24: Evidence Generation & Traceability
        var md5FindingCheck = assessMd5.Findings.FirstOrDefault(f => f.RuleId == "IPSEC-CRYPTO-002");
        Assert(md5FindingCheck != null &&
               !string.IsNullOrWhiteSpace(md5FindingCheck.Evidence) &&
               md5FindingCheck.Evidence.Contains("HMAC-MD5-96") &&
               !string.IsNullOrWhiteSpace(md5FindingCheck.Recommendation),
               "Scenario 24: Every finding contains concrete verifiable evidence referencing observed capture values",
               $"Evidence: {md5FindingCheck?.Evidence}");

        // -------------------------------------------------------------
        // SECTION C: ViewModels Synchronization & Real UI Integration
        // -------------------------------------------------------------
        Console.WriteLine("\n[SECTION C] ViewModels Synchronization & Event Pipeline");

        var assessmentVm = provider.GetRequiredService<SecurityAssessmentViewModel>();
        var findingsVm = provider.GetRequiredService<FindingsViewModel>();
        var recVm = provider.GetRequiredService<RecommendationsViewModel>();
        var dashVm = provider.GetRequiredService<DashboardViewModel>();

        // Trigger assessment pipeline with mixed vulnerabilities
        await assessmentService.AssessAsync(mixedVulnerabilities, policy);

        Assert(assessmentVm.HasAssessment == true && assessmentVm.DisplayRiskScore.Contains("100"),
               "ViewModel Sync: SecurityAssessmentViewModel receives AssessmentCompleted event and updates score",
               $"VM Score: {assessmentVm.DisplayRiskScore}, Risk Level: {assessmentVm.DisplayRiskLevel}");

        Assert(findingsVm.HasFindings == true && findingsVm.TotalFindingsCount >= 5,
               "ViewModel Sync: FindingsViewModel updates with real findings collection",
               $"VM Total Findings: {findingsVm.TotalFindingsCount}");

        // Test filtering in FindingsViewModel
        findingsVm.FilterCriticalCommand.Execute(null);
        Assert(findingsVm.Findings.Count == 0, "FindingsViewModel: Critical filter correctly filters 0 critical findings");

        findingsVm.FilterHighCommand.Execute(null);
        Assert(findingsVm.Findings.Count >= 3, "FindingsViewModel: High filter displays all High severity findings");

        findingsVm.FilterAllCommand.Execute(null);
        Assert(findingsVm.Findings.Count >= 5, "FindingsViewModel: All filter resets and displays all findings");

        Assert(recVm.HasRecommendations == true && recVm.TotalRecommendationsCount >= 5,
               "ViewModel Sync: RecommendationsViewModel populates prioritized recommendations list",
               $"VM Total Recommendations: {recVm.TotalRecommendationsCount}");

        Assert(dashVm.HasSecurityAssessment == true && dashVm.DisplaySecurityScore.Contains("100"),
               "ViewModel Sync: DashboardViewModel receives assessment and updates executive score card",
               $"Dashboard Score: {dashVm.DisplaySecurityScore}, Risk Level: {dashVm.DisplayRiskLevel}");

        // Phase 5 AI Analysis Tests
        var (aiPassed, aiFailed) = await IPsecSecurityAnalyzer.Tests.Services.AiAnalysisServiceTests.RunAllAsync();
        passed += aiPassed;
        failed += aiFailed;

        // Phase 6 Database, History & Reporting Tests
        var (phase6Passed, phase6Failed) = await IPsecSecurityAnalyzer.Tests.Services.Phase6VerificationTests.RunAllAsync();
        passed += phase6Passed;
        failed += phase6Failed;

        // Phase 7 End-to-End Integration & SIH Demo Readiness Tests
        var (phase7Passed, phase7Failed) = await IPsecSecurityAnalyzer.Tests.Services.Phase7IntegrationTests.RunAllAsync();
        passed += phase7Passed;
        failed += phase7Failed;

        Console.WriteLine("\n================================================================================");
        Console.WriteLine($"   Complete Test Suite: {passed} PASSED, {failed} FAILED");
        Console.WriteLine("================================================================================\n");

        return failed == 0 ? 0 : 1;
    }
}
