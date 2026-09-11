using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Interfaces;

/// <summary>
/// Service interface for dissecting IKEv1/IKEv2 handshakes, ESP transforms, SPI tracking, and SA proposals (Phase 3).
/// </summary>
public interface IIpsecAnalyzer
{
    /// <summary>
    /// Gets the current IPsec / IKE analysis result.
    /// </summary>
    Task<IpsecAnalysisResult> GetIpsecAnalysisAsync();
}
