using System.IO;
using System.Text.Json;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// JSON-ready settings persistence service.
/// </summary>
public class SettingsService : ISettingsService
{
    private static readonly string SettingsFilePath = Path.Combine(
        AppDomain.CurrentDomain.BaseDirectory,
        "appsettings.json"
    );

    private ApplicationSettings _settings = new();

    public ApplicationSettings Settings => _settings;

    public async Task<ApplicationSettings> LoadSettingsAsync()
    {
        try
        {
            if (File.Exists(SettingsFilePath))
            {
                var json = await File.ReadAllTextAsync(SettingsFilePath);
                var loaded = JsonSerializer.Deserialize<ApplicationSettings>(json);
                if (loaded != null)
                {
                    _settings = loaded;
                }
            }
        }
        catch
        {
            // Revert to defaults gracefully if JSON reading fails
            _settings = new ApplicationSettings();
        }

        return _settings;
    }

    public async Task SaveSettingsAsync(ApplicationSettings settings)
    {
        try
        {
            _settings = settings;
            var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(SettingsFilePath, json);
        }
        catch
        {
            // Gracefully ignore local write issues during Phase 1
        }
    }
}
