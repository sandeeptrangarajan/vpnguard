using System.Linq;
using System.Windows.Input;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for AI/ML Traffic Classification and Anomaly Detection.
/// Uses the single end-to-end analysis result as the source of truth.
/// </summary>
public class AiAnalysisViewModel : ViewModelBase
{
    private readonly IAiAnalysisService _aiAnalysisService;
    private readonly IPcapAnalyzer? _pcapAnalyzer;
    private readonly IAnalysisOrchestrator? _orchestrator;
    private AiAnalysisResult _aiResult = new();
    private bool _isAnalyzing;
    private string _statusMessage = "Analyze a PCAP to generate AI results.";

    public AiAnalysisViewModel(
        IAiAnalysisService aiAnalysisService,
        IPcapAnalyzer? pcapAnalyzer = null,
        IAnalysisOrchestrator? orchestrator = null)
    {
        _aiAnalysisService = aiAnalysisService;
        _pcapAnalyzer = pcapAnalyzer;
        _orchestrator = orchestrator;
        RunAnalysisCommand = new RelayCommand(async () => await RunAnalysisAsync(), () => !IsAnalyzing);

        if (_orchestrator != null)
        {
            _orchestrator.AnalysisCompleted += (s, report) =>
            {
                AiResult = FromReport(report);
                StatusMessage = report.HasAiAnalysis
                    ? $"Analysis complete — {report.AiTrafficType ?? "Unknown traffic"} ({(report.AiConfidence ?? 0) * 100:F1}% confidence)."
                    : "AI analysis was not available. See the error/status details from the analysis run.";
            };
        }
    }

    public ICommand RunAnalysisCommand { get; }

    public AiAnalysisResult AiResult
    {
        get => _aiResult;
        set
        {
            if (SetProperty(ref _aiResult, value))
            {
                OnPropertyChanged(nameof(IsModelConnected));
                OnPropertyChanged(nameof(HasResults));
                OnPropertyChanged(nameof(ModelStatusText));
            }
        }
    }

    public bool IsAnalyzing
    {
        get => _isAnalyzing;
        set => SetProperty(ref _isAnalyzing, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public bool IsModelConnected => _aiResult.IsModelConnected;
    public bool HasResults => _aiResult.IsModelConnected && _aiResult.TrafficType != null;
    public string ModelStatusText => _aiResult.IsModelConnected
        ? "AI Engine Connected"
        : (_aiResult.ErrorMessage ?? "Python AI environment is not configured.");

    private async Task RunAnalysisAsync()
    {
        IsAnalyzing = true;
        StatusMessage = "Running AI analysis...";
        try
        {
            var report = _orchestrator?.LastReportData;
            if (report != null && report.HasAiAnalysis)
            {
                AiResult = FromReport(report);
                StatusMessage = "AI results loaded from the latest completed analysis.";
                return;
            }

            var filePath = _pcapAnalyzer?.CurrentFile?.FilePath;
            if (_orchestrator != null && !string.IsNullOrWhiteSpace(filePath))
            {
                await _orchestrator.RunFullAnalysisAsync(filePath);
                return;
            }

            var packets = _pcapAnalyzer?.LastAnalysisResult?.PacketDetails;
            if (packets == null || packets.Count == 0)
            {
                AiResult = new AiAnalysisResult { IsModelConnected = false, ErrorMessage = "Load and analyze a PCAP file first." };
                StatusMessage = AiResult.ErrorMessage!;
                return;
            }

            // Compatibility fallback only when no orchestrator is available.
            AiResult = await _aiAnalysisService.GetAiAnalysisAsync(packets);
            StatusMessage = AiResult.IsModelConnected
                ? $"AI analysis complete — {AiResult.TrafficType ?? "Unknown"}."
                : AiResult.ErrorMessage ?? "AI analysis failed.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"AI analysis failed: {ex.Message}";
            AiResult = new AiAnalysisResult { IsModelConnected = false, ErrorMessage = ex.Message };
        }
        finally
        {
            IsAnalyzing = false;
        }
    }

    private static AiAnalysisResult FromReport(AnalysisReportData report) => new()
    {
        IsModelConnected = report.HasAiAnalysis,
        TrafficType = report.AiTrafficType,
        Prediction = report.AiPrediction,
        Confidence = report.AiConfidence,
        Explanation = report.AiExplanation,
        Anomalies = report.AiAnomalies.ToList(),
        TopFeatures = report.TopFeatures.ToList(),
        Features = report.AiFeatures.ToDictionary(k => k.Key, v => v.Value)
    };
}
