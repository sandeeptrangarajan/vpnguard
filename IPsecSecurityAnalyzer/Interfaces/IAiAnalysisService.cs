using IPsecSecurityAnalyzer.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IPsecSecurityAnalyzer.Interfaces;

/// <summary>
/// Service interface for AI/ML-driven protocol identification, traffic classification, and anomaly detection (Phase 5).
/// </summary>
public interface IAiAnalysisService
{
    /// <summary>
    /// Gets the AI traffic analysis and anomaly detection inference results.
    /// </summary>
    /// <param name="packets">Optional collection of packet metadata extracted from Phase 2/3. If null, a fallback result is returned.</param>
    Task<AiAnalysisResult> GetAiAnalysisAsync(IEnumerable<object>? packets = null);
}
