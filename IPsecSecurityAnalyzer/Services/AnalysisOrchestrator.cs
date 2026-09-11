using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Central orchestration engine coordinating the complete end-to-end pipeline:
/// PCAP Packet Extraction -> IPsec Dissection -> Security Rules -> AI Traffic Inference -> SQLite Persistence.
/// Guarantees single Session AnalysisId consistency and zero duplicate packet parsing.
/// </summary>
public class AnalysisOrchestrator : IAnalysisOrchestrator
{
    private readonly IPcapAnalyzer _pcapAnalyzer;
    private readonly IIpsecAnalyzer _ipsecAnalyzer;
    private readonly ISecurityAssessmentService _assessmentService;
    private readonly IAiAnalysisService _aiAnalysisService;
    private readonly IAnalysisHistoryService _historyService;
    private readonly ITsharkService _tsharkService;

    private bool _isAnalyzing;
    private string _currentProgressStatus = "Ready";
    private AnalysisReportData? _lastReportData;

    public bool IsAnalyzing => _isAnalyzing;
    public string CurrentProgressStatus => _currentProgressStatus;
    public AnalysisReportData? LastReportData => _lastReportData;

    public event EventHandler<AnalysisReportData>? AnalysisCompleted;
    public event EventHandler<string>? ProgressChanged;

    public AnalysisOrchestrator(
        IPcapAnalyzer pcapAnalyzer,
        IIpsecAnalyzer ipsecAnalyzer,
        ISecurityAssessmentService assessmentService,
        IAiAnalysisService aiAnalysisService,
        IAnalysisHistoryService historyService,
        ITsharkService tsharkService)
    {
        _pcapAnalyzer = pcapAnalyzer;
        _ipsecAnalyzer = ipsecAnalyzer;
        _assessmentService = assessmentService;
        _aiAnalysisService = aiAnalysisService;
        _historyService = historyService;
        _tsharkService = tsharkService;
    }

    public async Task<AnalysisReportData> RunFullAnalysisAsync(
        string filePath,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        // 1. Validation
        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new ArgumentException("Please select a PCAP file first.", nameof(filePath));
        }

        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException("Selected PCAP file could not be found.", filePath);
        }

        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        if (ext != ".pcap" && ext != ".pcapng")
        {
            throw new NotSupportedException($"Unsupported capture file format '{ext}'. Only .pcap and .pcapng files are supported.");
        }

        var fileInfo = new FileInfo(filePath);
        if (fileInfo.Length == 0)
        {
            throw new InvalidOperationException("The capture file is empty (0 bytes).");
        }

        if (!_tsharkService.IsTsharkAvailable())
        {
            throw new InvalidOperationException("TShark is not configured or could not be found.");
        }

        _isAnalyzing = true;

        void ReportStatus(string status)
        {
            _currentProgressStatus = status;
            progress?.Report(status);
            ProgressChanged?.Invoke(this, status);
        }

        try
        {
            // 2. Phase 2: Packet Extraction
            ReportStatus("Analyzing PCAP...");
            ReportStatus("Running packet analysis...");
            var pcapResult = await _pcapAnalyzer.AnalyzeAsync(filePath, cancellationToken);

            // 3. Phase 3: IPsec / IKE / ESP Dissection
            ReportStatus("Analyzing IPsec...");
            var ipsecResult = await _ipsecAnalyzer.GetIpsecAnalysisAsync();

            // 4. Phase 4: Security Assessment & Cryptographic Evaluation
            ReportStatus("Running security assessment...");
            var assessmentResult = await _assessmentService.AssessAsync(ipsecResult);

            // 5. Phase 5: AI Traffic Classification & Anomaly Detection
            ReportStatus("Running AI analysis...");
            AiAnalysisResult? aiResult = null;
            try
            {
                aiResult = await _aiAnalysisService.GetAiAnalysisAsync(pcapResult.PacketDetails);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[AnalysisOrchestrator] AI analysis fallback: {ex.Message}");
                aiResult = new AiAnalysisResult { IsModelConnected = false, ErrorMessage = ex.Message };
            }

            // 6. Phase 6: Snapshot Assembly & SQLite Persistence
            ReportStatus("Saving analysis...");

            var sessionId = Guid.NewGuid().ToString();
            var reportData = new AnalysisReportData
            {
                AnalysisId = sessionId,
                AnalysisTimestamp = DateTime.UtcNow,
                ApplicationVersion = Utilities.Constants.AppConstants.Version,
                FileName = fileInfo.Name,
                FilePath = fileInfo.FullName,
                FileSizeBytes = fileInfo.Length,
                CaptureDurationSeconds = pcapResult.Duration.TotalSeconds,
                TotalPackets = pcapResult.PacketCount,
                TotalBytes = pcapResult.TotalBytes,
                IpsecDetected = pcapResult.IpsecPacketCount > 0,
                IpsecPacketCount = pcapResult.IpsecPacketCount,
                IkePacketCount = pcapResult.IkePacketCount,
                EspPacketCount = pcapResult.EspPacketCount,
                AhPacketCount = pcapResult.AhPacketCount,
                TcpPacketCount = pcapResult.TcpPacketCount,
                UdpPacketCount = pcapResult.UdpPacketCount,
                IcmpPacketCount = pcapResult.Protocols.FirstOrDefault(p => p.ProtocolName.Equals("ICMP", StringComparison.OrdinalIgnoreCase))?.PacketCount ?? 0,
                ProtocolDistribution = pcapResult.Protocols.ToList()
            };

            // Phase 3 attributes
            if (ipsecResult != null && ipsecResult.IsAnalyzed)
            {
                reportData.HasIpsecAnalysis = true;
                reportData.IkeVersion = ipsecResult.IkevVersion;
                reportData.ExchangeType = ipsecResult.ExchangeType;
                reportData.AuthenticationMethod = ipsecResult.AuthenticationMethod;
                reportData.EncryptionAlgorithm = ipsecResult.EncryptionAlgorithm;
                reportData.IntegrityAlgorithm = ipsecResult.IntegrityAlgorithm;
                reportData.DhGroup = ipsecResult.DhGroup;
                reportData.PfsEnabled = ipsecResult.PfsEnabled;
                reportData.ReplayProtectionEnabled = ipsecResult.ReplayProtectionEnabled;
                reportData.IpsecMode = ipsecResult.IpsecMode;
                reportData.Spi = ipsecResult.Spi;
                reportData.KeyLifetime = ipsecResult.KeyLifetime;
                reportData.SaProposals = ipsecResult.SaProposals.ToList();
                reportData.Handshakes = ipsecResult.Handshakes.ToList();
                reportData.EspSessions = ipsecResult.EspSessions.ToList();
            }

            // Phase 4 attributes
            if (assessmentResult != null && assessmentResult.HasAssessment)
            {
                reportData.HasSecurityAssessment = true;
                reportData.OverallRiskScore = assessmentResult.OverallRiskScore;
                reportData.RiskLevel = assessmentResult.RiskLevel;
                reportData.AssessmentCoverage = assessmentResult.AssessmentCoverage;
                reportData.AssessedParameterCount = assessmentResult.AssessedParameterCount;
                reportData.UnknownParameterCount = assessmentResult.UnknownParameterCount;
                reportData.AssessmentSummary = assessmentResult.Summary;
                reportData.CriticalFindingCount = assessmentResult.CriticalCount;
                reportData.HighFindingCount = assessmentResult.HighCount;
                reportData.MediumFindingCount = assessmentResult.MediumCount;
                reportData.LowFindingCount = assessmentResult.LowCount;
                reportData.InformationalFindingCount = assessmentResult.InformationalCount;
                reportData.Findings = assessmentResult.Findings.ToList();
                reportData.Recommendations = assessmentResult.Recommendations.ToList();
            }

            // Phase 5 attributes
            if (aiResult != null && aiResult.IsModelConnected)
            {
                reportData.HasAiAnalysis = true;
                reportData.AiTrafficType = aiResult.TrafficType;
                reportData.AiConfidence = aiResult.Confidence;
                reportData.AiPrediction = aiResult.Prediction;
                reportData.AnomalyDetected = aiResult.HasAnomalies;
                reportData.AiExplanation = aiResult.Explanation;
                reportData.TopFeatures = aiResult.TopFeatures.ToList();
                reportData.AiFeatures = aiResult.Features.ToDictionary(k => k.Key, v => v.Value);
                reportData.AiAnomalies = aiResult.Anomalies.ToList();
            }

            // Save to SQLite
            await _historyService.SaveAnalysisAsync(reportData);

            _lastReportData = reportData;
            ReportStatus("Analysis completed successfully.");
            AnalysisCompleted?.Invoke(this, reportData);

            return reportData;
        }
        finally
        {
            _isAnalyzing = false;
        }
    }
}
