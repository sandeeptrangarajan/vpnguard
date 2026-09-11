using System.Collections.Generic;
using System.Threading.Tasks;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Interfaces;

/// <summary>
/// Service interface for generating and exporting PDF reports and JSON audit snapshots (Phase 6).
/// </summary>
public interface IReportService
{
    /// <summary>
    /// Generates a comprehensive PDF security assessment report from a complete analysis snapshot.
    /// </summary>
    Task<string> GeneratePdfReportAsync(AnalysisReportData reportData, string destinationPath);

    /// <summary>
    /// Generates a PDF security assessment report using the currently active analysis state.
    /// </summary>
    Task<string> GeneratePdfReportAsync(string destinationPath);

    /// <summary>
    /// Exports the full analysis snapshot to a structured JSON file.
    /// </summary>
    Task<string> ExportJsonAsync(AnalysisReportData reportData, string destinationPath);

    /// <summary>
    /// Retrieves a list of previously generated report file paths.
    /// </summary>
    Task<IReadOnlyList<string>> GetGeneratedReportsAsync();
}
