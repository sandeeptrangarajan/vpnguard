using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Interfaces;

/// <summary>
/// Service interface for persisting and querying historical analysis records via SQLite database (Phase 6).
/// </summary>
public interface IAnalysisHistoryService
{
    /// <summary>
    /// Event triggered when analysis history is modified (e.g. record added or deleted).
    /// </summary>
    event EventHandler? HistoryChanged;

    /// <summary>
    /// Retrieves all historical analysis records from SQLite.
    /// </summary>
    Task<IReadOnlyList<AnalysisHistory>> GetHistoryAsync();

    /// <summary>
    /// Retrieves all historical analysis records from SQLite.
    /// </summary>
    Task<IReadOnlyList<AnalysisHistory>> GetAnalysesAsync();

    /// <summary>
    /// Retrieves a complete analysis snapshot by its unique AnalysisId.
    /// </summary>
    Task<AnalysisReportData?> GetAnalysisByIdAsync(string analysisId);

    /// <summary>
    /// Saves a newly completed analysis run to history and SQLite database.
    /// </summary>
    Task AddHistoryRecordAsync(AnalysisHistory record);

    /// <summary>
    /// Saves a complete analysis snapshot to SQLite database and updates history.
    /// </summary>
    Task<bool> SaveAnalysisAsync(AnalysisReportData reportData);

    /// <summary>
    /// Deletes an analysis record and its snapshot from SQLite database by AnalysisId.
    /// </summary>
    Task<bool> DeleteAnalysisAsync(string analysisId);

    /// <summary>
    /// Searches and filters historical records based on query parameters.
    /// </summary>
    Task<IReadOnlyList<AnalysisHistory>> SearchAnalysesAsync(string? searchTerm = null, string? riskLevelFilter = null, bool? ipsecFilter = null, bool? anomalyFilter = null);

    /// <summary>
    /// Clears all historical analysis records from the SQLite database.
    /// </summary>
    Task<bool> ClearHistoryAsync();

    /// <summary>
    /// Gets the count of stored history records.
    /// </summary>
    Task<int> GetHistoryCountAsync();

    /// <summary>
    /// Gets the most recent analysis record, or null if history is empty.
    /// </summary>
    Task<AnalysisHistory?> GetLatestAnalysisAsync();
}
