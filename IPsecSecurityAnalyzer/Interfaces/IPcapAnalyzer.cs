using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Interfaces;

/// <summary>
/// Service interface for PCAP file loading, validation, and real packet dissection analysis via TShark.
/// </summary>
public interface IPcapAnalyzer
{
    /// <summary>
    /// Currently loaded PCAP file metadata, or null if none loaded.
    /// </summary>
    PcapFileInfo? CurrentFile { get; }

    /// <summary>
    /// Latest comprehensive analysis result from PCAP inspection, or null if not yet analyzed.
    /// </summary>
    PcapAnalysisResult? LastAnalysisResult { get; }

    /// <summary>
    /// Event triggered when the active PCAP file changes.
    /// </summary>
    event EventHandler<PcapFileInfo?>? FileChanged;

    /// <summary>
    /// Event triggered when PCAP analysis completes with real results.
    /// </summary>
    event EventHandler<PcapAnalysisResult?>? AnalysisCompleted;

    /// <summary>
    /// Loads and inspects basic file metadata from the specified PCAP/PCAPNG file path.
    /// </summary>
    /// <param name="filePath">Absolute path to .pcap or .pcapng file.</param>
    /// <returns>PcapFileInfo metadata.</returns>
    Task<PcapFileInfo> LoadPcapFileAsync(string filePath);

    /// <summary>
    /// Performs asynchronous deep packet inspection and protocol/IPsec dissection on the target PCAP file using TShark.
    /// </summary>
    /// <param name="filePath">Absolute path to .pcap or .pcapng file.</param>
    /// <param name="cancellationToken">Cancellation token to cancel ongoing TShark process.</param>
    /// <returns>Populated PcapAnalysisResult.</returns>
    Task<PcapAnalysisResult> AnalyzeAsync(string filePath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets aggregated traffic statistics from the last analysis.
    /// </summary>
    Task<TrafficStatistics> GetTrafficStatisticsAsync();
}
