using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Manages application-level page routing and navigation state in MVVM.
/// </summary>
public class NavigationService : INavigationService
{
    private NavigationPage _currentPage = NavigationPage.Dashboard;

    public NavigationPage CurrentPage => _currentPage;

    public event EventHandler<NavigationPage>? CurrentPageChanged;

    public void NavigateTo(NavigationPage page)
    {
        if (_currentPage != page)
        {
            _currentPage = page;
            CurrentPageChanged?.Invoke(this, page);
        }
    }
}
