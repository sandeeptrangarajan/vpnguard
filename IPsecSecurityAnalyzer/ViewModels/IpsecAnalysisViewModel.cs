using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for the IPsec / IKE Protocol Dissection Page.
/// Displays observable Phase 2 parameters from real PCAP packet inspection.
/// </summary>
public class IpsecAnalysisViewModel : ViewModelBase
{
    private readonly IIpsecAnalyzer _ipsecAnalyzer;
    private readonly IPcapAnalyzer _pcapAnalyzer;
    private IpsecAnalysisResult _analysisResult = new();

    public IpsecAnalysisViewModel(
        IIpsecAnalyzer ipsecAnalyzer,
        IPcapAnalyzer pcapAnalyzer)
    {
        _ipsecAnalyzer = ipsecAnalyzer;
        _pcapAnalyzer = pcapAnalyzer;

        _pcapAnalyzer.AnalysisCompleted += async (s, result) =>
        {
            await RefreshAnalysisAsync();
        };

        _ = RefreshAnalysisAsync();
    }

    public IpsecAnalysisResult AnalysisResult
    {
        get => _analysisResult;
        set => SetProperty(ref _analysisResult, value);
    }

    public async Task RefreshAnalysisAsync()
    {
        AnalysisResult = await _ipsecAnalyzer.GetIpsecAnalysisAsync();
    }
}
