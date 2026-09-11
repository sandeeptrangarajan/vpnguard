namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Real-time tracking and state information for an ESP tunnel session.
/// </summary>
public class EspSessionInfo
{
    public string Spi { get; set; } = "Unknown";
    public string Source { get; set; } = string.Empty;
    public string Destination { get; set; } = string.Empty;
    public long PacketCount { get; set; }
    public long TotalBytes { get; set; }
    public long FirstSequence { get; set; } = 1;
    public long LastSequence { get; set; } = 1;
    public int SequenceGaps { get; set; }
    public int DuplicateSequences { get; set; }
    public string ReplayStatus => DuplicateSequences > 0 ? $"Replays Detected ({DuplicateSequences})" : (SequenceGaps > 0 ? $"Gaps Observed ({SequenceGaps})" : "Strict In-Order");
    public string Mode { get; set; } = "Tunnel (ESP)";
    public string FormattedBytes
    {
        get
        {
            var bytes = TotalBytes;
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F2} KB";
            if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024.0):F2} MB";
            return $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} GB";
        }
    }
}
