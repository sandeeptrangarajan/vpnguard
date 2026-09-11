using System.Text.Json.Serialization;

namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Structured result containing comprehensive PCAP analysis, real packet statistics, protocol distribution, and IPsec detections.
/// Fully JSON serializable.
/// </summary>
public class PcapAnalysisResult
{
    public string FileName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public long FileSize { get; set; }
    public long PacketCount { get; set; }
    public string? FirstPacketTimestamp { get; set; }
    public string? LastPacketTimestamp { get; set; }
    public TimeSpan Duration { get; set; } = TimeSpan.Zero;
    public long TotalBytes { get; set; }

    public List<ProtocolStatistics> Protocols { get; set; } = new();

    public long IpsecPacketCount { get; set; }
    public long IkePacketCount { get; set; }
    public long EspPacketCount { get; set; }
    public long AhPacketCount { get; set; }

    public long TcpPacketCount { get; set; }
    public long UdpPacketCount { get; set; }
    public long Ipv4PacketCount { get; set; }
    public long Ipv6PacketCount { get; set; }

    public List<string> SourceAddresses { get; set; } = new();
    public List<string> DestinationAddresses { get; set; } = new();

    public List<PacketInfo> PacketDetails { get; set; } = new();
    public List<IpsecPacketInfo> IpsecPackets { get; set; } = new();

    // Observable IKE / ESP details extracted from PCAP (Phase 2 & Phase 3)
    public string IkeVersion { get; set; } = "Unknown";
    public string IkeExchangeType { get; set; } = "Unknown";
    public string IkeInitiatorSpi { get; set; } = "Unknown";
    public string IkeResponderSpi { get; set; } = "Unknown";
    public string IkeMessageId { get; set; } = "Unknown";
    public string EspSpi { get; set; } = "Unknown";

    // Phase 3 Deep Handshake Structures
    public List<IkeSaProposal> SaProposals { get; set; } = new();
    public List<IkeExchangeInfo> Handshakes { get; set; } = new();
    public List<EspSessionInfo> EspSessions { get; set; } = new();

    public string EncryptionAlgorithm { get; set; } = "Unknown";
    public string IntegrityAlgorithm { get; set; } = "Unknown";
    public string DhGroup { get; set; } = "Unknown";
    public string AuthenticationMethod { get; set; } = "Unknown";
    public string PrfAlgorithm { get; set; } = "Unknown";
    public string KeyLifetime { get; set; } = "Unknown";
    public bool? PfsEnabled { get; set; }
    public bool? ReplayProtectionEnabled { get; set; }
    public bool AggressiveModeDetected { get; set; }
    public bool NonceObserved { get; set; }
    public bool KeyExchangePayloadObserved { get; set; }

    // Non-serialized UI Helpers
    [JsonIgnore]
    public bool HasIpsecTraffic => IpsecPacketCount > 0;

    [JsonIgnore]
    public string DisplayIpsecDetected => HasIpsecTraffic ? "YES" : "NO";

    [JsonIgnore]
    public double IpsecPercentage => PacketCount > 0 ? (double)IpsecPacketCount / PacketCount * 100.0 : 0.0;

    [JsonIgnore]
    public string FormattedIpsecPercentage => $"{IpsecPercentage:F1}%";

    [JsonIgnore]
    public string FormattedDuration => Duration.TotalSeconds > 0 ? Duration.ToString(@"hh\:mm\:ss\.fff") : "00:00:00.000";

    [JsonIgnore]
    public string FormattedTotalBytes
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

    [JsonIgnore]
    public string FormattedFileSize
    {
        get
        {
            var bytes = FileSize;
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F2} KB";
            if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024.0):F2} MB";
            return $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} GB";
        }
    }
}
