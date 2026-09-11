using System;
using System.Threading;
using System.Threading.Tasks;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Interfaces;

/// <summary>
/// Orchestration contract coordinating the complete end-to-end analysis pipeline:
/// PCAP Extraction -> IPsec Dissection -> Security Rules -> AI Inference -> SQLite Persistence.
/// </summary>
public interface IAnalysisOrchestrator
{
    /// <summary>
    /// Indicates whether an analysis pipeline operation is currently in progress.
    /// </summary>
    bool IsAnalyzing { get; }

    /// <summary>
    /// Current progress message of the running analysis.
    /// </summary>
    string CurrentProgressStatus { get; }

    /// <summary>
    /// Most recent combined analysis report snapshot.
    /// </summary>
    AnalysisReportData? LastReportData { get; }

    /// <summary>
    /// Event fired when an analysis pipeline completes successfully.
    /// </summary>
    event EventHandler<AnalysisReportData>? AnalysisCompleted;

    /// <summary>
    /// Event fired when the analysis progress status updates.
    /// </summary>
    event EventHandler<string>? ProgressChanged;

    /// <summary>
    /// Executes the full multi-phase analysis pipeline on the given PCAP file.
    /// </summary>
    /// <param name="filePath">Absolute path to .pcap or .pcapng file.</param>
    /// <param name="progress">Optional progress reporter for UI status updates.</param>
    /// <param name="cancellationToken">Cancellation token to cancel ongoing execution.</param>
    /// <returns>Combined AnalysisReportData snapshot.</returns>
    Task<AnalysisReportData> RunFullAnalysisAsync(string filePath, IProgress<string>? progress = null, CancellationToken cancellationToken = default);
}
