using System.Windows;
using IPsecSecurityAnalyzer.ViewModels;

namespace IPsecSecurityAnalyzer.Views;

public partial class MainWindow : Window
{
    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
