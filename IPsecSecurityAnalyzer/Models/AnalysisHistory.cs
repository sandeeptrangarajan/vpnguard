using System;

namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Record of a previous PCAP security analysis stored in history and SQLite database.
/// Extended with Phase 6 comprehensive audit fields.
/// </summary>
public class AnalysisHistory
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string AnalysisId { get; set; } = Guid.NewGuid().ToString();
    public string FileName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string AnalysisType { get; set; } = "PCAP Static";
    public DateTime Date { get; set; } = DateTime.UtcNow;
    public double AnalysisDuration { get; set; }
    public string Status { get; set; } = "Completed";
    public long FileSizeBytes { get; set; }

    // Protocol info
    public bool IpsecDetected { get; set; }
    public string? IkeVersion { get; set; }
    public string? IpsecMode { get; set; }

    // Security Assessment
    public double? SecurityScore { get; set; }
    public RiskLevel RiskLevel { get; set; } = RiskLevel.Unknown;
    public int FindingCount { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public int InformationalCount { get; set; }

    // AI Analysis (Phase 5)
    public string? AiClassification { get; set; }
    public double? AiConfidence { get; set; }
    public bool AnomalyDetected { get; set; }
    public double? AnomalyScore { get; set; }
    public string? AiModelName { get; set; }
    public string? AiModelVersion { get; set; }
    public string? Notes { get; set; }

    // Formatted display helpers
    public string FormattedDate => Date.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
    public string FormattedRiskLevel => RiskLevel.ToString();
    public string FormattedSecurityScore => SecurityScore.HasValue ? $"{SecurityScore.Value:F0}" : "N/A";
    public string FormattedIpsecStatus => IpsecDetected ? "Yes" : "No";
    public string FormattedAiClassification => !string.IsNullOrWhiteSpace(AiClassification) ? AiClassification : "N/A";
    public string FormattedAiConfidence => AiConfidence.HasValue ? $"{AiConfidence.Value * 100:F0}%" : "N/A";
    public string FormattedAnomalyStatus => AnomalyDetected ? "Potentially Unusual" : "Normal";
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
