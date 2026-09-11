namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Aggregated network traffic metrics and statistics extracted from PCAP or live stream.
/// </summary>
public class TrafficStatistics
{
    public long? TotalPackets { get; set; }
    public long? TotalBytes { get; set; }
    public TimeSpan? Duration { get; set; }
    public int? SourceCount { get; set; }
    public int? DestinationCount { get; set; }

    public string FormattedPackets => TotalPackets.HasValue ? TotalPackets.Value.ToString("N0") : "Not available";

    public string FormattedBytes
    {
        get
        {
            if (!TotalBytes.HasValue) return "Not available";
            var bytes = TotalBytes.Value;
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F2} KB";
            if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024.0):F2} MB";
            return $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} GB";
        }
    }

    public string FormattedDuration => Duration.HasValue ? Duration.Value.ToString(@"hh\:mm\:ss\.fff") : "Not available";
    public string FormattedSourceCount => SourceCount.HasValue ? SourceCount.Value.ToString() : "Not available";
    public string FormattedDestinationCount => DestinationCount.HasValue ? DestinationCount.Value.ToString() : "Not available";
}
