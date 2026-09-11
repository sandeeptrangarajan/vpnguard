using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using IPsecSecurityAnalyzer.Data;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;
using IPsecSecurityAnalyzer.Services;

namespace IPsecSecurityAnalyzer.Tests.Services;

/// <summary>
/// Phase 6 Verification Test Suite: Database, Analysis History, and Reporting.
/// Tests SQLite persistence, search/filter, snapshot serialization, report generation, and empty state handling.
/// Uses an isolated, temporary SQLite test database to ensure zero production contamination.
/// </summary>
public static class Phase6VerificationTests
{
    public static async Task<(int passed, int failed)> RunAllAsync()
    {
        int passed = 0;
        int failed = 0;

        void Assert(bool condition, string testName, string? details = null)
        {
            if (condition)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("[PASS] ");
                Console.ResetColor();
                Console.WriteLine(testName);
                if (!string.IsNullOrEmpty(details))
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"       └─ {details}");
                    Console.ResetColor();
                }
                passed++;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("[FAIL] ");
                Console.ResetColor();
                Console.WriteLine(testName);
                if (!string.IsNullOrEmpty(details))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"       └─ Failure detail: {details}");
                    Console.ResetColor();
                }
                failed++;
            }
        }

        Console.WriteLine();
        Console.WriteLine("================================================================================");
        Console.WriteLine("   Phase 6: Database, History & Reporting Test Suite");
        Console.WriteLine("================================================================================");

        var testDbName = $"vpnguard_test_{Guid.NewGuid():N}.db";
        var testDbPath = Path.Combine(Path.GetTempPath(), testDbName);

        Func<AppDbContext> testContextFactory = () =>
        {
            var options = new DbContextOptionsBuilder<AppDbContext>()
                .UseSqlite($"Data Source={testDbPath}")
                .Options;
            return new AppDbContext(options);
        };

        try
        {
            IAnalysisHistoryService historyService = new AnalysisHistoryService(testContextFactory);
            IReportService reportService = new ReportService();

            // Test 1: SQLite Database Initialization & Empty History Handling
            {
                var initialList = await historyService.GetAnalysesAsync();
                Assert(initialList != null && initialList.Count == 0,
                    "Database: Automatically initialized and initial history is cleanly empty (No Fake Data)");

                var count = await historyService.GetHistoryCountAsync();
                Assert(count == 0, "Database: Initial history count is exactly 0");

                var latest = await historyService.GetLatestAnalysisAsync();
                Assert(latest == null, "Database: GetLatestAnalysisAsync returns null when history is empty");
            }

            // Test 2: Persisting Complete Analysis Snapshot (Phase 2 -> 3 -> 4 -> 5)
            var analysisId = Guid.NewGuid().ToString();
            var testReport = new AnalysisReportData
            {
                AnalysisId = analysisId,
                FileName = "test_ipsec_audit.pcap",
                FilePath = @"C:\captures\test_ipsec_audit.pcap",
                FileSizeBytes = 1024 * 512, // 512 KB
                CaptureDurationSeconds = 12.5,
                TotalPackets = 1200,
                TotalBytes = 524288,
                IpsecDetected = true,
                IpsecPacketCount = 850,
                IkePacketCount = 50,
                EspPacketCount = 800,
                HasIpsecAnalysis = true,
                IkeVersion = "IKEv2",
                EncryptionAlgorithm = "AES-256-GCM",
                IntegrityAlgorithm = "None (AEAD)",
                DhGroup = "Group 19 (256-bit ECP)",
                PfsEnabled = true,
                ReplayProtectionEnabled = true,
                HasSecurityAssessment = true,
                OverallRiskScore = 15.0,
                RiskLevel = RiskLevel.Low,
                AssessmentCoverage = 100.0,
                AssessedParameterCount = 8,
                UnknownParameterCount = 0,
                CriticalFindingCount = 0,
                HighFindingCount = 0,
                MediumFindingCount = 1,
                HasAiAnalysis = true,
                AiTrafficType = "VoIP",
                AiConfidence = 0.94,
                AiPrediction = "Normal",
                AnomalyDetected = false
            };

            testReport.Findings.Add(new SecurityFinding
            {
                RuleId = "IPSEC-CONFIG-003",
                Title = "Moderate SA Lifetime",
                Severity = SeverityLevel.Medium,
                ObservedValue = "28800s",
                Recommendation = "Maintain lifetime under 8 hours.",
                Evidence = "SA Lifetime set to 28800 seconds in Proposal 1."
            });

            testReport.Recommendations.Add(new SecurityRecommendation
            {
                Title = "Maintain Configured SA Lifetime",
                Priority = SeverityLevel.Medium,
                Recommendation = "Configure SA lifetime <= 28800s.",
                Reason = "Limits key exposure window."
            });

            {
                var saved = await historyService.SaveAnalysisAsync(testReport);
                Assert(saved, "SaveAnalysisAsync: Successfully persists complete analysis snapshot to SQLite");

                var updatedCount = await historyService.GetHistoryCountAsync();
                Assert(updatedCount == 1, "SaveAnalysisAsync: History count increments to 1", $"Count: {updatedCount}");
            }

            // Test 3: Retrieve Snapshot & Data Integrity
            {
                var retrieved = await historyService.GetAnalysisByIdAsync(analysisId);
                Assert(retrieved != null, "GetAnalysisByIdAsync: Retrieves stored snapshot by AnalysisId");
                Assert(retrieved?.FileName == "test_ipsec_audit.pcap", "GetAnalysisByIdAsync: File name preserved exactly");
                Assert(retrieved?.IkeVersion == "IKEv2", "GetAnalysisByIdAsync: IKE version preserved");
                Assert(retrieved?.OverallRiskScore == 15.0, "GetAnalysisByIdAsync: Security score preserved");
                Assert(retrieved?.Findings.Count == 1, "GetAnalysisByIdAsync: Security findings list preserved intact");
                Assert(retrieved?.Findings[0].RuleId == "IPSEC-CONFIG-003", "GetAnalysisByIdAsync: Finding RuleId verified");
                Assert(retrieved?.AiTrafficType == "VoIP", "GetAnalysisByIdAsync: AI Traffic Type preserved");
                Assert(retrieved?.AiConfidence == 0.94, "GetAnalysisByIdAsync: AI Confidence preserved");
            }

            // Test 4: History Search & Filtering
            {
                // Search by file name
                var searchHit = await historyService.SearchAnalysesAsync(searchTerm: "ipsec_audit");
                Assert(searchHit.Count == 1, "Search: Query by PCAP filename matches expected record");

                var searchMiss = await historyService.SearchAnalysesAsync(searchTerm: "nonexistent_file");
                Assert(searchMiss.Count == 0, "Search: Non-matching term returns 0 results");

                // Filter by Risk Level
                var filterRisk = await historyService.SearchAnalysesAsync(riskLevelFilter: "Low");
                Assert(filterRisk.Count == 1, "Filter: RiskLevel filter 'Low' matches expected record");

                var filterRiskMiss = await historyService.SearchAnalysesAsync(riskLevelFilter: "Critical");
                Assert(filterRiskMiss.Count == 0, "Filter: RiskLevel filter 'Critical' correctly excludes record");

                // Filter by IPsec status
                var filterIpsec = await historyService.SearchAnalysesAsync(ipsecFilter: true);
                Assert(filterIpsec.Count == 1, "Filter: IPsecDetected filter matches record");

                // Filter by Anomaly status
                var filterAnomaly = await historyService.SearchAnalysesAsync(anomalyFilter: true);
                Assert(filterAnomaly.Count == 0, "Filter: Anomaly filter excludes normal profile record");
            }

            // Test 5: Missing AI Result Graceful Handling (Defensive verification)
            {
                var partialAnalysisId = Guid.NewGuid().ToString();
                var partialReport = new AnalysisReportData
                {
                    AnalysisId = partialAnalysisId,
                    FileName = "partial_no_ai.pcap",
                    FileSizeBytes = 1024,
                    IpsecDetected = false,
                    HasAiAnalysis = false, // AI unavailable
                    AiTrafficType = null,
                    AiConfidence = null,
                    HasSecurityAssessment = false
                };

                await historyService.SaveAnalysisAsync(partialReport);
                var retrievedPartial = await historyService.GetAnalysisByIdAsync(partialAnalysisId);
                Assert(retrievedPartial != null, "Partial Data: Preserves record when AI analysis is unavailable");
                Assert(retrievedPartial?.HasAiAnalysis == false, "Partial Data: Correctly flags HasAiAnalysis as false");
                Assert(retrievedPartial?.AiTrafficType == null, "Partial Data: Does NOT invent fake AI classification");
                Assert(retrievedPartial?.AiConfidence == null, "Partial Data: Does NOT invent fake AI confidence");
            }

            // Test 6: Report Service - JSON Export
            {
                var jsonExportPath = Path.Combine(Path.GetTempPath(), $"export_test_{Guid.NewGuid():N}.json");
                try
                {
                    var exportedPath = await reportService.ExportJsonAsync(testReport, jsonExportPath);
                    Assert(File.Exists(exportedPath), "ReportService: JSON export creates valid physical file", exportedPath);

                    var jsonContent = await File.ReadAllTextAsync(exportedPath);
                    var deserialized = JsonSerializer.Deserialize<AnalysisReportData>(jsonContent);
                    Assert(deserialized?.AnalysisId == testReport.AnalysisId, "ReportService: JSON export contains complete deserializable snapshot");
                    Assert(deserialized?.Findings.Count == 1, "ReportService: JSON export contains findings array");
                }
                finally
                {
                    if (File.Exists(jsonExportPath)) File.Delete(jsonExportPath);
                }
            }

            // Test 7: Report Service - PDF Generation
            {
                var pdfExportPath = Path.Combine(Path.GetTempPath(), $"report_test_{Guid.NewGuid():N}.pdf");
                try
                {
                    var exportedPath = await reportService.GeneratePdfReportAsync(testReport, pdfExportPath);
                    Assert(File.Exists(exportedPath), "ReportService: PDF generation creates physical PDF document", exportedPath);

                    var fileInfo = new FileInfo(exportedPath);
                    Assert(fileInfo.Length > 500, "ReportService: PDF document has valid payload size", $"{fileInfo.Length} bytes");

                    var fileHeader = new byte[8];
                    using (var fs = File.OpenRead(exportedPath))
                    {
                        fs.Read(fileHeader, 0, 8);
                    }
                    var headerStr = System.Text.Encoding.ASCII.GetString(fileHeader);
                    Assert(headerStr.StartsWith("%PDF-"), "ReportService: PDF document header complies with ISO 32000 specification");
                }
                finally
                {
                    if (File.Exists(pdfExportPath)) File.Delete(pdfExportPath);
                }
            }

            // Test 8: Deleting History Record
            {
                var deleted = await historyService.DeleteAnalysisAsync(analysisId);
                Assert(deleted, "DeleteAnalysisAsync: Successfully deletes record by AnalysisId");

                var verifyDeleted = await historyService.GetAnalysisByIdAsync(analysisId);
                Assert(verifyDeleted == null, "DeleteAnalysisAsync: Record is no longer retrievable from SQLite");
            }

            // Test 9: Clear All History
            {
                var cleared = await historyService.ClearHistoryAsync();
                Assert(cleared, "ClearHistoryAsync: Clears all remaining records from SQLite");

                var finalCount = await historyService.GetHistoryCountAsync();
                Assert(finalCount == 0, "ClearHistoryAsync: Final count is 0");
            }
        }
        finally
        {
            // Clean up temporary SQLite database file
            if (File.Exists(testDbPath))
            {
                try { File.Delete(testDbPath); } catch { }
            }
        }

        Console.WriteLine();
        Console.WriteLine($"Phase 6 Database & Report Tests: {passed} passed, {failed} failed");
        return (passed, failed);
    }
}
