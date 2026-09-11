namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Configuration and environment settings for the IPsec Security Analyzer.
/// </summary>
public class ApplicationSettings
{
    public string Theme { get; set; } = "Dark SOC";
    public string AnalyzerPath { get; set; } = string.Empty;
    public string PythonPath { get; set; } = string.Empty;
    public string TsharkPath { get; set; } = string.Empty;
    public string DatabasePath { get; set; } = "ipsec_analyzer.db";
    public string ModelPath { get; set; } = string.Empty;

    // Environmental / Status metadata
    public string ApplicationVersion { get; set; } = "v1.0.0 (SIH26160)";
    public string AnalyzerStatus { get; set; } = "TShark Dissector Ready";
    public string AiEngineStatus { get; set; } = "Python AI Engine Ready (scikit-learn)";
    public string DatabaseStatus { get; set; } = "SQLite Persistence Ready";
}
