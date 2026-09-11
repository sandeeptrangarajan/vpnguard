using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// Production ViewModel for Security Reports Generation and PDF/JSON Audit Export (Phase 6).
/// Integrates directly with real active analysis state and persisted history records.
/// </summary>
public class ReportsViewModel : ViewModelBase
{
    private readonly IReportService _reportService;
    private readonly IAnalysisHistoryService _historyService;
    private readonly IFileDialogService _fileDialogService;
    private readonly IPcapAnalyzer _pcapAnalyzer;

    private ObservableCollection<string> _generatedReports = new();
    private string _statusMessage = "Ready to generate security reports.";
    private bool _isGenerating;

    public ReportsViewModel(
        IReportService reportService,
        IAnalysisHistoryService historyService,
        IFileDialogService fileDialogService,
        IPcapAnalyzer pcapAnalyzer)
    {
        _reportService = reportService;
        _historyService = historyService;
        _fileDialogService = fileDialogService;
        _pcapAnalyzer = pcapAnalyzer;

        GenerateReportCommand = new RelayCommand(async () => await ExecuteGenerateReportAsync(), () => !IsGenerating);
        ExportPdfCommand = new RelayCommand(async () => await ExecuteGenerateReportAsync(), () => !IsGenerating);
        ExportJsonCommand = new RelayCommand(async () => await ExecuteExportJsonAsync(), () => !IsGenerating);

        _ = LoadReportsAsync();
    }

    public ObservableCollection<string> GeneratedReports
    {
        get => _generatedReports;
        set => SetProperty(ref _generatedReports, value);
    }

    public bool HasReports => _generatedReports.Count > 0;

    public bool IsGenerating
    {
        get => _isGenerating;
        set => SetProperty(ref _isGenerating, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public ICommand GenerateReportCommand { get; }
    public ICommand ExportPdfCommand { get; }
    public ICommand ExportJsonCommand { get; }

    private async Task LoadReportsAsync()
    {
        var list = await _reportService.GetGeneratedReportsAsync();
        GeneratedReports.Clear();
        foreach (var item in list)
        {
            GeneratedReports.Add(item);
        }
        OnPropertyChanged(nameof(HasReports));
    }

    private async Task ExecuteGenerateReportAsync()
    {
        var activePcap = _pcapAnalyzer.LastAnalysisResult?.FileName ?? "Current_Capture";
        var defaultName = $"VPNGuard_Report_{Path.GetFileNameWithoutExtension(activePcap)}_{DateTime.Now:yyyyMMdd_HHmmss}.pdf";

        var savePath = _fileDialogService.SaveFileDialog(defaultName, "PDF Security Report (*.pdf)|*.pdf");
        if (string.IsNullOrEmpty(savePath))
            return;

        IsGenerating = true;
        StatusMessage = "Generating comprehensive PDF security audit report...";

        try
        {
            await _reportService.GeneratePdfReportAsync(savePath);
            await LoadReportsAsync();
            StatusMessage = $"PDF report generated successfully: {Path.GetFileName(savePath)}";

            MessageBox.Show($"Security report generated successfully:\n\n{savePath}", "Report Generated", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            StatusMessage = $"PDF generation failed: {ex.Message}";
            MessageBox.Show($"Failed to generate report: {ex.Message}", "Report Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsGenerating = false;
        }
    }

    private async Task ExecuteExportJsonAsync()
    {
        var activePcap = _pcapAnalyzer.LastAnalysisResult?.FileName ?? "Current_Capture";
        var defaultName = $"VPNGuard_Audit_{Path.GetFileNameWithoutExtension(activePcap)}_{DateTime.Now:yyyyMMdd_HHmmss}.json";

        var savePath = _fileDialogService.SaveFileDialog(defaultName, "JSON Audit Snapshot (*.json)|*.json");
        if (string.IsNullOrEmpty(savePath))
            return;

        IsGenerating = true;
        StatusMessage = "Exporting JSON audit snapshot...";

        try
        {
            var latest = await _historyService.GetLatestAnalysisAsync();
            AnalysisReportData? reportData = null;
            if (latest != null)
            {
                reportData = await _historyService.GetAnalysisByIdAsync(latest.AnalysisId);
            }

            if (reportData == null)
            {
                // Create minimal report data from current state
                reportData = new AnalysisReportData
                {
                    FileName = _pcapAnalyzer.LastAnalysisResult?.FileName ?? "No active capture",
                    AnalysisTimestamp = DateTime.UtcNow
                };
            }

            await _reportService.ExportJsonAsync(reportData, savePath);
            await LoadReportsAsync();
            StatusMessage = $"JSON snapshot exported: {Path.GetFileName(savePath)}";

            MessageBox.Show($"JSON audit snapshot exported successfully:\n\n{savePath}", "JSON Exported", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            StatusMessage = $"JSON export failed: {ex.Message}";
            MessageBox.Show($"Failed to export JSON: {ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsGenerating = false;
        }
    }
}
