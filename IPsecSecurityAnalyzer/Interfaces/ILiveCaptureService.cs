using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Interfaces;

/// <summary>
/// Service interface for network interface discovery, live packet streaming, and PCAP capture generation.
/// </summary>
public interface ILiveCaptureService
{
    /// <summary>
    /// Indicates whether a live capture session is currently active.
    /// </summary>
    bool IsCapturing { get; }

    /// <summary>
    /// Total count of packets captured in the current or most recent session.
    /// </summary>
    int CapturedPacketsCount { get; }

    /// <summary>
    /// Total bytes captured in the current or most recent session.
    /// </summary>
    long CapturedBytesCount { get; }

    /// <summary>
    /// Path to the generated PCAP file for the active or completed session.
    /// </summary>
    string? LastCapturedPcapPath { get; }

    /// <summary>
    /// Fired whenever a new packet is captured or streamed.
    /// </summary>
    event EventHandler<PacketInfo>? PacketReceived;

    /// <summary>
    /// Fired when engine capture status changes.
    /// </summary>
    event EventHandler<string>? StatusChanged;

    /// <summary>
    /// Fired when capture completes, passing the path to the captured PCAP.
    /// </summary>
    event EventHandler<string>? CaptureStopped;

    /// <summary>
    /// Discovers available network interfaces on the local host and virtual testbed streams.
    /// </summary>
    Task<IReadOnlyList<string>> GetAvailableInterfacesAsync();

    /// <summary>
    /// Initiates a live packet capture on the specified interface.
    /// </summary>
    Task StartCaptureAsync(string interfaceName, TimeSpan? duration = null);

    /// <summary>
    /// Stops any active live packet capture session.
    /// </summary>
    Task StopCaptureAsync();
}

