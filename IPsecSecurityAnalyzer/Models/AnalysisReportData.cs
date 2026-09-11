using System;
using System.Collections.Generic;

namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Unified snapshot representing a complete analysis run across Phase 2, 3, 4, and 5.
/// Source of truth for SQLite persistence, history viewing, PDF reporting, and JSON export.
/// Strictly adheres to the "No Fake Data" rule.
/// </summary>
public class AnalysisReportData
{
    // 1. Metadata
    public string AnalysisId { get; set; } = Guid.NewGuid().ToString();
    public DateTime AnalysisTimestamp { get; set; } = DateTime.UtcNow;
    public string ApplicationVersion { get; set; } = "v1.0.0 (SIH26160)";
    public string Notes { get; set; } = string.Empty;

    // 2. PCAP & File Information
    public string FileName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public double CaptureDurationSeconds { get; set; }
    public long TotalPackets { get; set; }
    public long TotalBytes { get; set; }

    // 3. Traffic Statistics & Protocol Distribution
    public bool IpsecDetected { get; set; }
    public long IpsecPacketCount { get; set; }
    public long IkePacketCount { get; set; }
    public long EspPacketCount { get; set; }
    public long AhPacketCount { get; set; }
    public long TcpPacketCount { get; set; }
    public long UdpPacketCount { get; set; }
    public long IcmpPacketCount { get; set; }
    public long Ipv4PacketCount { get; set; }
    public long Ipv6PacketCount { get; set; }
    public List<ProtocolStatistics> ProtocolDistribution { get; set; } = new();

    // 4. IPsec / IKE Protocol Dissection (Phase 3)
    public bool HasIpsecAnalysis { get; set; }
    public string? IkeVersion { get; set; }
    public string? ExchangeType { get; set; }
    public string? AuthenticationMethod { get; set; }
    public string? EncryptionAlgorithm { get; set; }
    public string? IntegrityAlgorithm { get; set; }
    public string? DhGroup { get; set; }
    public bool? PfsEnabled { get; set; }
    public bool? ReplayProtectionEnabled { get; set; }
    public string? IpsecMode { get; set; }
    public string? Spi { get; set; }
    public string? KeyLifetime { get; set; }
    public List<IkeSaProposal> SaProposals { get; set; } = new();
    public List<IkeExchangeInfo> Handshakes { get; set; } = new();
    public List<EspSessionInfo> EspSessions { get; set; } = new();

    // 5. Security Assessment Engine (Phase 4)
    public bool HasSecurityAssessment { get; set; }
    public double? OverallRiskScore { get; set; }
    public RiskLevel RiskLevel { get; set; } = RiskLevel.Unknown;
    public double AssessmentCoverage { get; set; }
    public int AssessedParameterCount { get; set; }
    public int UnknownParameterCount { get; set; }
    public string AssessmentSummary { get; set; } = string.Empty;
    public int CriticalFindingCount { get; set; }
    public int HighFindingCount { get; set; }
    public int MediumFindingCount { get; set; }
    public int LowFindingCount { get; set; }
    public int InformationalFindingCount { get; set; }
    public List<SecurityFinding> Findings { get; set; } = new();
    public List<SecurityRecommendation> Recommendations { get; set; } = new();

    // 6. AI-Based Traffic Classification & Anomaly Analysis (Phase 5)
    public bool HasAiAnalysis { get; set; }
    public string? AiTrafficType { get; set; }
    public double? AiConfidence { get; set; }
    public string? AiPrediction { get; set; }
    public bool AnomalyDetected { get; set; }
    public string? AiExplanation { get; set; }
    public List<FeatureImportance> TopFeatures { get; set; } = new();
    public Dictionary<string, string> AiFeatures { get; set; } = new();
    public List<string> AiAnomalies { get; set; } = new();
    public string? AiModelName { get; set; }
    public string? AiModelVersion { get; set; }

    // Display Helpers
    public string FormattedTimestamp => AnalysisTimestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public string FormattedRiskScore => OverallRiskScore.HasValue ? $"{OverallRiskScore.Value:F0} / 100" : "Not Assessable";
    public string FormattedRiskLevel => RiskLevel.ToString();
    public string FormattedCoverage => $"{AssessmentCoverage:F0}%";
    public string FormattedFileSize
    {
        get
        {
            if (FileSizeBytes >= 1024 * 1024)
                return $"{FileSizeBytes / (1024.0 * 1024.0):F2} MB";
            if (FileSizeBytes >= 1024)
                return $"{FileSizeBytes / 1024.0:F2} KB";
            return $"{FileSizeBytes} B";
        }
    }
}
