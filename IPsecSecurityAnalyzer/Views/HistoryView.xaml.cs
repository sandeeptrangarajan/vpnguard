using System.Windows.Controls;
using System.Windows.Input;
using IPsecSecurityAnalyzer.Models;
using IPsecSecurityAnalyzer.ViewModels;

namespace IPsecSecurityAnalyzer.Views;

public partial class HistoryView : UserControl
{
    public HistoryView()
    {
        InitializeComponent();
    }

    private void OnRowDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is HistoryViewModel vm && sender is DataGridRow row && row.Item is AnalysisHistory item)
        {
            _ = vm.ViewDetailsAsync(item);
        }
    }
}
