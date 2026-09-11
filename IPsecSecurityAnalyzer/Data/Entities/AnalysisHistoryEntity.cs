using System;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Data.Entities;

/// <summary>
/// SQLite entity storing historical analysis audit runs with summary metrics and serialized complete snapshot.
/// </summary>
public class AnalysisHistoryEntity
{
    public int Id { get; set; }
    public string AnalysisId { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public DateTime AnalysisDate { get; set; }
    public double AnalysisDuration { get; set; }

    public bool IpsecDetected { get; set; }
    public string? IkeVersion { get; set; }
    public string? IpsecMode { get; set; }

    public double? SecurityScore { get; set; }
    public string RiskLevel { get; set; } = "Unknown";
    public int FindingCount { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public int InformationalCount { get; set; }

    public string? AiClassification { get; set; }
    public double? AiConfidence { get; set; }
    public bool AnomalyDetected { get; set; }
    public double? AnomalyScore { get; set; }
    public string? AiModelName { get; set; }
    public string? AiModelVersion { get; set; }
    public string? Notes { get; set; }

    /// <summary>
    /// Full JSON-serialized AnalysisReportData snapshot for instant retrieval without reprocessing.
    /// </summary>
    public string SnapshotJson { get; set; } = string.Empty;
}
