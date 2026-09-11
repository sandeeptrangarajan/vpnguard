namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Detailed metadata for an individual packet extracted from a PCAP/PCAPNG capture.
/// </summary>
public class PacketInfo
{
    public long PacketNumber { get; set; }
    public string Timestamp { get; set; } = string.Empty;
    /// <summary>Unix epoch timestamp in seconds, retained for machine-learning features.</summary>
    public double Epoch { get; set; }
    public string Source { get; set; } = string.Empty;
    public string Destination { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public long Length { get; set; }
    public string Info { get; set; } = string.Empty;
    /// <summary>Observed IPsec SPI when available.</summary>
    public string Spi { get; set; } = string.Empty;
}
