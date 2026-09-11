using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Dissects IKE / ESP transforms, security associations, and key exchanges.
/// Populates detailed Phase 3 parameters from real PCAP dissections.
/// </summary>
public class IpsecAnalyzer : IIpsecAnalyzer
{
    private readonly IPcapAnalyzer _pcapAnalyzer;

    public IpsecAnalyzer(IPcapAnalyzer pcapAnalyzer)
    {
        _pcapAnalyzer = pcapAnalyzer;
    }

    public Task<IpsecAnalysisResult> GetIpsecAnalysisAsync()
    {
        var lastResult = _pcapAnalyzer.LastAnalysisResult;
        if (lastResult == null)
        {
            return Task.FromResult(new IpsecAnalysisResult
            {
                IsAnalyzed = false
            });
        }

        var result = new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            IkePacketCount = lastResult.IkePacketCount,
            EspPacketCount = lastResult.EspPacketCount,
            AhPacketCount = lastResult.AhPacketCount,
            PacketCount = lastResult.IpsecPacketCount,
            SaProposals = new List<IkeSaProposal>(lastResult.SaProposals),
            Handshakes = new List<IkeExchangeInfo>(lastResult.Handshakes),
            EspSessions = new List<EspSessionInfo>(lastResult.EspSessions),
            AggressiveModeDetected = lastResult.AggressiveModeDetected,
            NonceObserved = lastResult.NonceObserved,
            KeyExchangePayloadObserved = lastResult.KeyExchangePayloadObserved,
            PfsEnabled = lastResult.PfsEnabled,
            ReplayProtectionEnabled = lastResult.ReplayProtectionEnabled
        };

        if (lastResult.IkePacketCount > 0)
        {
            result.IkevVersion = lastResult.IkeVersion != "Unknown" ? lastResult.IkeVersion : "IKE Detected";
            result.ExchangeType = lastResult.IkeExchangeType != "Unknown" ? lastResult.IkeExchangeType : "Unknown";
        }

        if (lastResult.EncryptionAlgorithm != "Unknown")
        {
            result.EncryptionAlgorithm = lastResult.EncryptionAlgorithm;
        }
        else if (lastResult.SaProposals.Count > 0 && lastResult.SaProposals[0].EncryptionAlgorithm != "Unknown")
        {
            result.EncryptionAlgorithm = lastResult.SaProposals[0].EncryptionAlgorithm;
        }

        if (lastResult.IntegrityAlgorithm != "Unknown")
        {
            result.IntegrityAlgorithm = lastResult.IntegrityAlgorithm;
        }
        else if (lastResult.SaProposals.Count > 0 && lastResult.SaProposals[0].IntegrityAlgorithm != "Unknown")
        {
            result.IntegrityAlgorithm = lastResult.SaProposals[0].IntegrityAlgorithm;
        }

        if (lastResult.DhGroup != "Unknown")
        {
            result.DhGroup = lastResult.DhGroup;
        }
        else if (lastResult.SaProposals.Count > 0 && lastResult.SaProposals[0].DhGroup != "Unknown")
        {
            result.DhGroup = lastResult.SaProposals[0].DhGroup;
        }

        if (lastResult.AuthenticationMethod != "Unknown")
        {
            result.AuthenticationMethod = lastResult.AuthenticationMethod;
        }
        else if (lastResult.SaProposals.Count > 0 && lastResult.SaProposals[0].AuthenticationMethod != "Unknown")
        {
            result.AuthenticationMethod = lastResult.SaProposals[0].AuthenticationMethod;
        }

        if (lastResult.PrfAlgorithm != "Unknown")
        {
            result.PrfAlgorithm = lastResult.PrfAlgorithm;
        }
        else if (lastResult.SaProposals.Count > 0 && lastResult.SaProposals[0].PrfAlgorithm != "Unknown")
        {
            result.PrfAlgorithm = lastResult.SaProposals[0].PrfAlgorithm;
        }

        if (lastResult.KeyLifetime != "Unknown")
        {
            result.KeyLifetime = lastResult.KeyLifetime;
        }
        else if (lastResult.SaProposals.Count > 0 && lastResult.SaProposals[0].LifeDuration != "Default / Unspecified")
        {
            result.KeyLifetime = lastResult.SaProposals[0].LifeDuration;
        }

        if (lastResult.EspPacketCount > 0)
        {
            result.Protocol = "ESP";
            result.Spi = lastResult.EspSpi != "Unknown" ? lastResult.EspSpi : "Observed in stream";
            result.IpsecMode = "Tunnel (ESP)";
        }
        else if (lastResult.IkePacketCount > 0)
        {
            result.Protocol = "ISAKMP / IKE";
            result.Spi = lastResult.IkeInitiatorSpi != "Unknown" ? lastResult.IkeInitiatorSpi : "Observed in stream";
        }
        else if (lastResult.AhPacketCount > 0)
        {
            result.Protocol = "AH";
            result.IpsecMode = "Transport / Tunnel (AH)";
        }
        else
        {
            result.Protocol = "None";
            result.TrafficType = "No IPsec traffic detected";
        }

        if (lastResult.HasIpsecTraffic)
        {
            result.TrafficType = $"IPsec ({lastResult.IpsecPacketCount:N0} packets: {lastResult.IkePacketCount:N0} IKE, {lastResult.EspPacketCount:N0} ESP, {lastResult.AhPacketCount:N0} AH)";
        }

        if (lastResult.SourceAddresses.Count > 0)
        {
            result.SourceAddress = string.Join(", ", lastResult.SourceAddresses.Take(3));
        }

        if (lastResult.DestinationAddresses.Count > 0)
        {
            result.DestinationAddress = string.Join(", ", lastResult.DestinationAddresses.Take(3));
        }

        return Task.FromResult(result);
    }
}
