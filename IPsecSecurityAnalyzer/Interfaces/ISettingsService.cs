using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Interfaces;

/// <summary>
/// Service interface for loading and saving application preferences and engine paths.
/// </summary>
public interface ISettingsService
{
    /// <summary>
    /// Current loaded application settings.
    /// </summary>
    ApplicationSettings Settings { get; }

    /// <summary>
    /// Loads settings from disk or default profile.
    /// </summary>
    Task<ApplicationSettings> LoadSettingsAsync();

    /// <summary>
    /// Persists settings changes to storage.
    /// </summary>
    Task SaveSettingsAsync(ApplicationSettings settings);
}
