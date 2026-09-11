namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Detailed record of an individual IKE handshake or exchange message.
/// </summary>
public class IkeExchangeInfo
{
    public long PacketNumber { get; set; }
    public string Timestamp { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string Destination { get; set; } = string.Empty;
    public string Version { get; set; } = "IKEv2";
    public string ExchangeType { get; set; } = string.Empty;
    public string InitiatorSpi { get; set; } = string.Empty;
    public string ResponderSpi { get; set; } = string.Empty;
    public string MessageId { get; set; } = "0";
    public string PayloadsSummary { get; set; } = string.Empty;
    public bool HasKeyExchange { get; set; }
    public string DhGroup { get; set; } = "None";
    public bool HasNonce { get; set; }
    public bool IsAggressiveMode { get; set; }
    public bool PfsDetected { get; set; }
    public string Role => ResponderSpi == "0000000000000000" || ResponderSpi == "0x0000000000000000" || string.IsNullOrEmpty(ResponderSpi) ? "Initiator Request" : "Responder Response";
}
