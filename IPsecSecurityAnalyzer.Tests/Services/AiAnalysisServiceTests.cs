using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;
using IPsecSecurityAnalyzer.Services;

namespace IPsecSecurityAnalyzer.Tests.Services;

/// <summary>
/// Phase 5 AI Analysis Service verification tests.
/// Uses the same custom console-based test runner as Phase 4.
/// Called from Program.Main in Phase4VerificationTests.cs.
/// </summary>
public static class AiAnalysisServiceTests
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
        Console.WriteLine("   Phase 5: AI Analysis Service Tests");
        Console.WriteLine("================================================================================");

        // Test 1: AiAnalysisResult default display helpers
        {
            var result = new AiAnalysisResult();
            Assert(result.DisplayProtocol == "Awaiting analysis", "AiResult.DisplayProtocol default is 'Awaiting analysis'");
            Assert(result.DisplayTrafficType == "Awaiting analysis", "AiResult.DisplayTrafficType default is 'Awaiting analysis'");
            Assert(result.DisplayPrediction == "Awaiting analysis", "AiResult.DisplayPrediction default is 'Awaiting analysis'");
            Assert(result.DisplayConfidence == "Awaiting analysis", "AiResult.DisplayConfidence default is 'Awaiting analysis'");
            Assert(result.DisplayExplanation == "No explanation available.", "AiResult.DisplayExplanation default is 'No explanation available.'");
            Assert(!result.HasAnomalies, "AiResult.HasAnomalies default is false");
            Assert(!result.HasTopFeatures, "AiResult.HasTopFeatures default is false");
            Assert(result.DisplayAnomalySummary == "No anomalies detected.", "AiResult.DisplayAnomalySummary default is 'No anomalies detected.'");
        }

        // Test 2: AiAnalysisResult populated display helpers
        {
            var result = new AiAnalysisResult
            {
                IsModelConnected = true,
                TrafficType = "VoIP",
                Confidence = 0.95,
                Prediction = "Normal",
                Explanation = "Test explanation",
                Anomalies = new List<string> { "Potentially unusual traffic pattern" },
                TopFeatures = new List<FeatureImportance>
                {
                    new() { Name = "packet_size", Importance = 0.15 }
                }
            };

            Assert(result.DisplayTrafficType == "AI-Inferred: VoIP", "AiResult.DisplayTrafficType shows 'AI-Inferred: VoIP'", result.DisplayTrafficType);
            Assert(result.DisplayConfidence == "AI Confidence: 95.0%", "AiResult.DisplayConfidence shows 'AI Confidence: 95.0%'", result.DisplayConfidence);
            Assert(result.DisplayPrediction == "Normal", "AiResult.DisplayPrediction shows 'Normal'");
            Assert(result.DisplayExplanation == "Test explanation", "AiResult.DisplayExplanation shows explanation");
            Assert(result.HasAnomalies, "AiResult.HasAnomalies is true when anomalies present");
            Assert(result.HasTopFeatures, "AiResult.HasTopFeatures is true when features present");
            Assert(result.TopFeatures[0].DisplayImportance == "15.00%", "FeatureImportance.DisplayImportance formats correctly", result.TopFeatures[0].DisplayImportance);
        }

        // Test 3: AiAnalysisService returns a result (fallback or real)
        {
            IAiAnalysisService service = new AiAnalysisService();
            var result = await service.GetAiAnalysisAsync();
            Assert(result != null, "AiAnalysisService.GetAiAnalysisAsync returns non-null result");
        }

        // Test 4: AiAnalysisService with null packets returns a result
        {
            IAiAnalysisService service = new AiAnalysisService();
            var result = await service.GetAiAnalysisAsync(null);
            Assert(result != null, "AiAnalysisService.GetAiAnalysisAsync(null) returns non-null result");
        }

        // Test 5: FeatureImportance model
        {
            var fi = new FeatureImportance { Name = "avg_packet_size", Importance = 0.1234 };
            Assert(fi.Name == "avg_packet_size", "FeatureImportance.Name set correctly");
            Assert(fi.DisplayImportance == "12.34%", "FeatureImportance.DisplayImportance formats correctly", fi.DisplayImportance);
        }

        Console.WriteLine();
        Console.WriteLine($"Phase 5 AI Tests: {passed} passed, {failed} failed");
        return (passed, failed);
    }
}

