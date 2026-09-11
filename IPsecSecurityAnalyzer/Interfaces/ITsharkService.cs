namespace IPsecSecurityAnalyzer.Interfaces;

/// <summary>
/// Execution output and status for TShark invocation.
/// </summary>
public class TsharkExecutionResult
{
    public int ExitCode { get; set; } = -1;
    public string StandardOutput { get; set; } = string.Empty;
    public string StandardError { get; set; } = string.Empty;
    public bool IsSuccess => ExitCode == 0 && !IsCancelled && !IsTimeout;
    public bool IsTimeout { get; set; }
    public bool IsCancelled { get; set; }
}

/// <summary>
/// Service interface for detecting, probing, and executing the TShark packet dissector engine.
/// </summary>
public interface ITsharkService
{
    /// <summary>
    /// Checks if TShark is detected either at the given custom path, configured path, or system paths.
    /// </summary>
    bool IsTsharkAvailable(string? customPath = null);

    /// <summary>
    /// Locates the absolute path to the tshark executable if present, or null if not found.
    /// </summary>
    string? FindTsharkPath(string? customPath = null);

    /// <summary>
    /// Probes TShark for its real version string by executing 'tshark --version'.
    /// </summary>
    Task<string?> GetTsharkVersionAsync(string? customPath = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Executes TShark with the specified arguments directly via Process without unsafe shell wrappers.
    /// </summary>
    Task<TsharkExecutionResult> ExecuteAsync(
        IEnumerable<string> arguments,
        string? customPath = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default);
}
