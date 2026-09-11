namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Machine learning / AI classification and anomaly detection results (Phase 5).
/// </summary>
public class AiAnalysisResult
{
    public bool IsModelConnected { get; set; } = false;
    public string? Protocol { get; set; }
    public string? TrafficType { get; set; }
    public string? Prediction { get; set; }
    public double? Confidence { get; set; }
    public Dictionary<string, string> Features { get; set; } = new();
    public List<string> Anomalies { get; set; } = new();
    public string? Explanation { get; set; }
    public List<FeatureImportance> TopFeatures { get; set; } = new();
    public string? ErrorMessage { get; set; }

    public string DisplayProtocol => !string.IsNullOrWhiteSpace(Protocol) ? Protocol : "Awaiting analysis";
    public string DisplayTrafficType => !string.IsNullOrWhiteSpace(TrafficType) ? $"AI-Inferred: {TrafficType}" : "Awaiting analysis";
    public string DisplayPrediction => !string.IsNullOrWhiteSpace(Prediction) ? Prediction : "Awaiting analysis";
    public string DisplayConfidence => Confidence.HasValue ? $"AI Confidence: {Confidence.Value * 100:F1}%" : "Awaiting analysis";
    public string DisplayExplanation => !string.IsNullOrWhiteSpace(Explanation) ? Explanation : "No explanation available.";
    public bool HasAnomalies => Anomalies.Count > 0;
    public bool HasTopFeatures => TopFeatures.Count > 0;
    public string DisplayAnomalySummary => HasAnomalies ? string.Join("; ", Anomalies) : "No anomalies detected.";
}

/// <summary>
/// Represents a single feature's importance in the AI model's decision.
/// </summary>
public class FeatureImportance
{
    public string Name { get; set; } = string.Empty;
    public double Importance { get; set; }
    public string DisplayImportance => $"{Importance * 100:F2}%";
}
