namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Detailed metadata for an individual IPsec (IKE, ESP, or AH) packet extracted from the capture.
/// </summary>
public class IpsecPacketInfo
{
    public long PacketNumber { get; set; }
    public string Timestamp { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string Destination { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public string Spi { get; set; } = "Unknown";
    public string SequenceNumber { get; set; } = "Unknown";
    public long Length { get; set; }
    public string Info { get; set; } = string.Empty;
}
