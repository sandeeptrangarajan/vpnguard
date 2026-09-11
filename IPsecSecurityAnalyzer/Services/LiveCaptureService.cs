using System.Net.NetworkInformation;
using IPsecSecurityAnalyzer.Interfaces;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Handles network interface querying and live streaming foundation.
/// </summary>
public class LiveCaptureService : ILiveCaptureService
{
    public bool IsCapturing => false;

    public Task<IReadOnlyList<string>> GetAvailableInterfacesAsync()
    {
        var interfaces = new List<string>();

        try
        {
            var nics = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var nic in nics)
            {
                if (nic.OperationalStatus == OperationalStatus.Up)
                {
                    interfaces.Add($"{nic.Name} ({nic.Description})");
                }
            }
        }
        catch
        {
            // Fallback gracefully if network interface querying is restricted
        }

        if (interfaces.Count == 0)
        {
            interfaces.Add("No active interfaces detected");
        }

        return Task.FromResult<IReadOnlyList<string>>(interfaces);
    }

    public Task StartCaptureAsync(string interfaceName, TimeSpan? duration = null)
    {
        // Intentionally not active in Phase 1
        return Task.CompletedTask;
    }

    public Task StopCaptureAsync()
    {
        // Intentionally not active in Phase 1
        return Task.CompletedTask;
    }
}
