namespace IPsecSecurityAnalyzer.Interfaces;

/// <summary>
/// Service interface for network interface discovery and live packet streaming.
/// </summary>
public interface ILiveCaptureService
{
    /// <summary>
    /// Indicates whether a live capture session is currently active.
    /// </summary>
    bool IsCapturing { get; }

    /// <summary>
    /// Discovers available network interfaces on the local host.
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
