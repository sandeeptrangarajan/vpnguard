namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Aggregated metric statistics for a specific protocol detected in the packet capture.
/// </summary>
public class ProtocolStatistics
{
    public string ProtocolName { get; set; } = string.Empty;
    public long PacketCount { get; set; }
    public long ByteCount { get; set; }
    public double Percentage { get; set; }

    public string FormattedPercentage => $"{Percentage:F1}%";

    public string FormattedBytes
    {
        get
        {
            var bytes = ByteCount;
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F2} KB";
            if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024.0):F2} MB";
            return $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} GB";
        }
    }
}
