using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using IPsecSecurityAnalyzer.Data;
using IPsecSecurityAnalyzer.Data.Entities;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Production SQLite-backed implementation of IAnalysisHistoryService for Phase 6.
/// Handles persistent local storage, asynchronous database operations, robust error recovery, and search/filtering.
/// </summary>
public class AnalysisHistoryService : IAnalysisHistoryService
{
    private readonly Func<AppDbContext> _contextFactory;
    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true
    };

    public event EventHandler? HistoryChanged;

    public AnalysisHistoryService(Func<AppDbContext>? contextFactory = null)
    {
        _contextFactory = contextFactory ?? (() => new AppDbContext());
        _ = EnsureDatabaseCreatedAsync();
    }

    private async Task EnsureDatabaseCreatedAsync()
    {
        try
        {
            await Task.Run(async () =>
            {
                using var context = _contextFactory();
                await context.Database.EnsureCreatedAsync();
            });
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AnalysisHistoryService] SQLite initialization warning: {ex.Message}");
        }
    }

    public async Task<IReadOnlyList<AnalysisHistory>> GetHistoryAsync()
    {
        return await GetAnalysesAsync();
    }

    public async Task<IReadOnlyList<AnalysisHistory>> GetAnalysesAsync()
    {
        try
        {
            return await Task.Run(async () =>
            {
                using var context = _contextFactory();
                await context.Database.EnsureCreatedAsync();

                var entities = await context.AnalysisHistories
                    .AsNoTracking()
                    .OrderByDescending(e => e.AnalysisDate)
                    .ToListAsync();

                return entities.Select(MapToModel).ToList();
            });
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AnalysisHistoryService] Failed to get analyses: {ex.Message}");
            return new List<AnalysisHistory>();
        }
    }

    public async Task<AnalysisReportData?> GetAnalysisByIdAsync(string analysisId)
    {
        if (string.IsNullOrWhiteSpace(analysisId))
            return null;

        try
        {
            return await Task.Run(async () =>
            {
                using var context = _contextFactory();
                await context.Database.EnsureCreatedAsync();

                var entity = await context.AnalysisHistories
                    .AsNoTracking()
                    .FirstOrDefaultAsync(e => e.AnalysisId == analysisId);

                if (entity == null || string.IsNullOrWhiteSpace(entity.SnapshotJson))
                    return null;

                return JsonSerializer.Deserialize<AnalysisReportData>(entity.SnapshotJson, _jsonOptions);
            });
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AnalysisHistoryService] Failed to get analysis by ID {analysisId}: {ex.Message}");
            return null;
        }
    }

    public async Task AddHistoryRecordAsync(AnalysisHistory record)
    {
        if (record == null) return;

        try
        {
            await Task.Run(async () =>
            {
                using var context = _contextFactory();
                await context.Database.EnsureCreatedAsync();

                var entity = new AnalysisHistoryEntity
                {
                    AnalysisId = string.IsNullOrWhiteSpace(record.AnalysisId) ? record.Id : record.AnalysisId,
                    FileName = record.FileName,
                    FilePath = record.FilePath,
                    FileSizeBytes = record.FileSizeBytes,
                    AnalysisDate = record.Date,
                    AnalysisDuration = record.AnalysisDuration,
                    IpsecDetected = record.IpsecDetected,
                    IkeVersion = record.IkeVersion,
                    IpsecMode = record.IpsecMode,
                    SecurityScore = record.SecurityScore,
                    RiskLevel = record.RiskLevel.ToString(),
                    FindingCount = record.FindingCount,
                    CriticalCount = record.CriticalCount,
                    HighCount = record.HighCount,
                    MediumCount = record.MediumCount,
                    LowCount = record.LowCount,
                    InformationalCount = record.InformationalCount,
                    AiClassification = record.AiClassification,
                    AiConfidence = record.AiConfidence,
                    AnomalyDetected = record.AnomalyDetected,
                    AnomalyScore = record.AnomalyScore,
                    AiModelName = record.AiModelName,
                    AiModelVersion = record.AiModelVersion,
                    Notes = record.Notes,
                    SnapshotJson = JsonSerializer.Serialize(new AnalysisReportData
                    {
                        AnalysisId = record.AnalysisId,
                        FileName = record.FileName,
                        FilePath = record.FilePath,
                        FileSizeBytes = record.FileSizeBytes,
                        AnalysisTimestamp = record.Date,
                        IpsecDetected = record.IpsecDetected,
                        IkeVersion = record.IkeVersion,
                        IpsecMode = record.IpsecMode,
                        OverallRiskScore = record.SecurityScore,
                        RiskLevel = record.RiskLevel,
                        CriticalFindingCount = record.CriticalCount,
                        HighFindingCount = record.HighCount,
                        MediumFindingCount = record.MediumCount,
                        LowFindingCount = record.LowCount,
                        InformationalFindingCount = record.InformationalCount,
                        AiTrafficType = record.AiClassification,
                        AiConfidence = record.AiConfidence,
                        AnomalyDetected = record.AnomalyDetected
                    }, _jsonOptions)
                };

                context.AnalysisHistories.Add(entity);
                await context.SaveChangesAsync();
            });

            HistoryChanged?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AnalysisHistoryService] Failed to add history record: {ex.Message}");
        }
    }

    public async Task<bool> SaveAnalysisAsync(AnalysisReportData reportData)
    {
        if (reportData == null) return false;

        try
        {
            return await Task.Run(async () =>
            {
                using var context = _contextFactory();
                await context.Database.EnsureCreatedAsync();

                var existing = await context.AnalysisHistories
                    .FirstOrDefaultAsync(e => e.AnalysisId == reportData.AnalysisId);

                var snapshotJson = JsonSerializer.Serialize(reportData, _jsonOptions);

                if (existing != null)
                {
                    existing.FileName = reportData.FileName;
                    existing.FilePath = reportData.FilePath;
                    existing.FileSizeBytes = reportData.FileSizeBytes;
                    existing.AnalysisDate = reportData.AnalysisTimestamp;
                    existing.AnalysisDuration = reportData.CaptureDurationSeconds;
                    existing.IpsecDetected = reportData.IpsecDetected;
                    existing.IkeVersion = reportData.IkeVersion;
                    existing.IpsecMode = reportData.IpsecMode;
                    existing.SecurityScore = reportData.OverallRiskScore;
                    existing.RiskLevel = reportData.RiskLevel.ToString();
                    existing.FindingCount = reportData.Findings.Count;
                    existing.CriticalCount = reportData.CriticalFindingCount;
                    existing.HighCount = reportData.HighFindingCount;
                    existing.MediumCount = reportData.MediumFindingCount;
                    existing.LowCount = reportData.LowFindingCount;
                    existing.InformationalCount = reportData.InformationalFindingCount;
                    existing.AiClassification = reportData.AiTrafficType;
                    existing.AiConfidence = reportData.AiConfidence;
                    existing.AnomalyDetected = reportData.AnomalyDetected;
                    existing.AiModelName = reportData.AiModelName;
                    existing.AiModelVersion = reportData.AiModelVersion;
                    existing.Notes = reportData.Notes;
                    existing.SnapshotJson = snapshotJson;
                }
                else
                {
                    var entity = new AnalysisHistoryEntity
                    {
                        AnalysisId = reportData.AnalysisId,
                        FileName = reportData.FileName,
                        FilePath = reportData.FilePath,
                        FileSizeBytes = reportData.FileSizeBytes,
                        AnalysisDate = reportData.AnalysisTimestamp,
                        AnalysisDuration = reportData.CaptureDurationSeconds,
                        IpsecDetected = reportData.IpsecDetected,
                        IkeVersion = reportData.IkeVersion,
                        IpsecMode = reportData.IpsecMode,
                        SecurityScore = reportData.OverallRiskScore,
                        RiskLevel = reportData.RiskLevel.ToString(),
                        FindingCount = reportData.Findings.Count,
                        CriticalCount = reportData.CriticalFindingCount,
                        HighCount = reportData.HighFindingCount,
                        MediumCount = reportData.MediumFindingCount,
                        LowCount = reportData.LowFindingCount,
                        InformationalCount = reportData.InformationalFindingCount,
                        AiClassification = reportData.AiTrafficType,
                        AiConfidence = reportData.AiConfidence,
                        AnomalyDetected = reportData.AnomalyDetected,
                        AiModelName = reportData.AiModelName,
                        AiModelVersion = reportData.AiModelVersion,
                        Notes = reportData.Notes,
                        SnapshotJson = snapshotJson
                    };
                    context.AnalysisHistories.Add(entity);
                }

                await context.SaveChangesAsync();
                return true;
            });
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AnalysisHistoryService] Failed to save analysis: {ex.Message}");
            return false;
        }
        finally
        {
            HistoryChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public async Task<bool> DeleteAnalysisAsync(string analysisId)
    {
        if (string.IsNullOrWhiteSpace(analysisId))
            return false;

        try
        {
            var result = await Task.Run(async () =>
            {
                using var context = _contextFactory();
                await context.Database.EnsureCreatedAsync();

                var entity = await context.AnalysisHistories
                    .FirstOrDefaultAsync(e => e.AnalysisId == analysisId);

                if (entity == null)
                    return false;

                context.AnalysisHistories.Remove(entity);
                await context.SaveChangesAsync();
                return true;
            });

            if (result)
            {
                HistoryChanged?.Invoke(this, EventArgs.Empty);
            }
            return result;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AnalysisHistoryService] Failed to delete analysis {analysisId}: {ex.Message}");
            return false;
        }
    }

    public async Task<IReadOnlyList<AnalysisHistory>> SearchAnalysesAsync(
        string? searchTerm = null,
        string? riskLevelFilter = null,
        bool? ipsecFilter = null,
        bool? anomalyFilter = null)
    {
        try
        {
            return await Task.Run(async () =>
            {
                using var context = _contextFactory();
                await context.Database.EnsureCreatedAsync();

                var query = context.AnalysisHistories.AsNoTracking().AsQueryable();

                if (!string.IsNullOrWhiteSpace(searchTerm))
                {
                    var term = searchTerm.Trim().ToLowerInvariant();
                    query = query.Where(e =>
                        e.FileName.ToLower().Contains(term) ||
                        e.AnalysisId.ToLower().Contains(term));
                }

                if (!string.IsNullOrWhiteSpace(riskLevelFilter) && riskLevelFilter != "All")
                {
                    query = query.Where(e => e.RiskLevel == riskLevelFilter);
                }

                if (ipsecFilter.HasValue)
                {
                    query = query.Where(e => e.IpsecDetected == ipsecFilter.Value);
                }

                if (anomalyFilter.HasValue)
                {
                    query = query.Where(e => e.AnomalyDetected == anomalyFilter.Value);
                }

                var entities = await query
                    .OrderByDescending(e => e.AnalysisDate)
                    .ToListAsync();

                return entities.Select(MapToModel).ToList();
            });
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AnalysisHistoryService] Search failed: {ex.Message}");
            return new List<AnalysisHistory>();
        }
    }

    public async Task<bool> ClearHistoryAsync()
    {
        try
        {
            var result = await Task.Run(async () =>
            {
                using var context = _contextFactory();
                await context.Database.EnsureCreatedAsync();

                context.AnalysisHistories.RemoveRange(context.AnalysisHistories);
                await context.SaveChangesAsync();
                return true;
            });

            HistoryChanged?.Invoke(this, EventArgs.Empty);
            return result;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AnalysisHistoryService] Failed to clear history: {ex.Message}");
            return false;
        }
    }

    public async Task<int> GetHistoryCountAsync()
    {
        try
        {
            return await Task.Run(async () =>
            {
                using var context = _contextFactory();
                await context.Database.EnsureCreatedAsync();
                return await context.AnalysisHistories.CountAsync();
            });
        }
        catch
        {
            return 0;
        }
    }

    public async Task<AnalysisHistory?> GetLatestAnalysisAsync()
    {
        try
        {
            return await Task.Run(async () =>
            {
                using var context = _contextFactory();
                await context.Database.EnsureCreatedAsync();

                var latest = await context.AnalysisHistories
                    .AsNoTracking()
                    .OrderByDescending(e => e.AnalysisDate)
                    .FirstOrDefaultAsync();

                return latest != null ? MapToModel(latest) : null;
            });
        }
        catch
        {
            return null;
        }
    }

    private static AnalysisHistory MapToModel(AnalysisHistoryEntity entity)
    {
        Enum.TryParse<RiskLevel>(entity.RiskLevel, true, out var risk);
        return new AnalysisHistory
        {
            Id = entity.Id.ToString(),
            AnalysisId = entity.AnalysisId,
            FileName = entity.FileName,
            FilePath = entity.FilePath,
            FileSizeBytes = entity.FileSizeBytes,
            Date = entity.AnalysisDate,
            AnalysisDuration = entity.AnalysisDuration,
            IpsecDetected = entity.IpsecDetected,
            IkeVersion = entity.IkeVersion,
            IpsecMode = entity.IpsecMode,
            SecurityScore = entity.SecurityScore,
            RiskLevel = risk,
            FindingCount = entity.FindingCount,
            CriticalCount = entity.CriticalCount,
            HighCount = entity.HighCount,
            MediumCount = entity.MediumCount,
            LowCount = entity.LowCount,
            InformationalCount = entity.InformationalCount,
            AiClassification = entity.AiClassification,
            AiConfidence = entity.AiConfidence,
            AnomalyDetected = entity.AnomalyDetected,
            AnomalyScore = entity.AnomalyScore,
            AiModelName = entity.AiModelName,
            AiModelVersion = entity.AiModelVersion,
            Notes = entity.Notes
        };
    }
}
