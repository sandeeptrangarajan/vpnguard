using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Interfaces;

/// <summary>
/// Service interface for navigating across application views within MVVM architecture.
/// </summary>
public interface INavigationService
{
    /// <summary>
    /// Currently active navigation page.
    /// </summary>
    NavigationPage CurrentPage { get; }

    /// <summary>
    /// Event raised whenever the active navigation page changes.
    /// </summary>
    event EventHandler<NavigationPage>? CurrentPageChanged;

    /// <summary>
    /// Navigates to the designated page.
    /// </summary>
    void NavigateTo(NavigationPage page);
}
