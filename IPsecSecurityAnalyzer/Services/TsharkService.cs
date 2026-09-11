using System.Diagnostics;
using System.IO;
using System.Text;
using IPsecSecurityAnalyzer.Interfaces;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Direct execution and discovery service for the TShark packet dissection engine.
/// Operates directly on the tshark binary without shell wrappers.
/// </summary>
public class TsharkService : ITsharkService
{
    private readonly ISettingsService _settingsService;
    private static readonly TimeSpan DefaultExecutionTimeout = TimeSpan.FromSeconds(60);

    public TsharkService(ISettingsService settingsService)
    {
        _settingsService = settingsService;
    }

    public bool IsTsharkAvailable(string? customPath = null)
    {
        return !string.IsNullOrEmpty(FindTsharkPath(customPath));
    }

    public string? FindTsharkPath(string? customPath = null)
    {
        // 1. Check custom path argument if specified
        if (!string.IsNullOrWhiteSpace(customPath))
        {
            var trimmed = customPath.Trim('\"', '\'', ' ');
            if (File.Exists(trimmed))
            {
                return Path.GetFullPath(trimmed);
            }
            if (Directory.Exists(trimmed))
            {
                var candidate = Path.Combine(trimmed, "tshark.exe");
                if (File.Exists(candidate)) return candidate;
                var candidateNonExe = Path.Combine(trimmed, "tshark");
                if (File.Exists(candidateNonExe)) return candidateNonExe;
            }
            return null;
        }

        // 2. Check path from ApplicationSettings
        var configuredPath = _settingsService.Settings?.TsharkPath;
        if (!string.IsNullOrWhiteSpace(configuredPath))
        {
            var trimmed = configuredPath.Trim('\"', '\'', ' ');
            if (File.Exists(trimmed))
            {
                return Path.GetFullPath(trimmed);
            }
            if (Directory.Exists(trimmed))
            {
                var candidate = Path.Combine(trimmed, "tshark.exe");
                if (File.Exists(candidate)) return candidate;
                var candidateNonExe = Path.Combine(trimmed, "tshark");
                if (File.Exists(candidateNonExe)) return candidateNonExe;
            }
        }

        // 3. Check well-known installation locations on Windows
        var standardWindowsPaths = new[]
        {
            @"C:\Program Files\Wireshark\tshark.exe",
            @"C:\Program Files (x86)\Wireshark\tshark.exe",
            @"D:\Program Files\Wireshark\tshark.exe",
            @"C:\Wireshark\tshark.exe",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Wireshark", "tshark.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Wireshark", "tshark.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Wireshark", "tshark.exe")
        };

        foreach (var path in standardWindowsPaths)
        {
            if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
            {
                return path;
            }
        }

        // 4. Check system PATH environment variable
        var pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrWhiteSpace(pathEnv))
        {
            var entries = pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);
            foreach (var entry in entries)
            {
                try
                {
                    var exeCandidate = Path.Combine(entry.Trim(), "tshark.exe");
                    if (File.Exists(exeCandidate)) return Path.GetFullPath(exeCandidate);

                    var unixCandidate = Path.Combine(entry.Trim(), "tshark");
                    if (File.Exists(unixCandidate)) return Path.GetFullPath(unixCandidate);
                }
                catch
                {
                    // Ignore path probing errors on malformed PATH entries
                }
            }
        }

        // 5. Unix/Linux/macOS standard fallbacks
        var standardUnixPaths = new[]
        {
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            "/opt/homebrew/bin/tshark",
            "/usr/sbin/tshark"
        };

        foreach (var path in standardUnixPaths)
        {
            if (File.Exists(path))
            {
                return path;
            }
        }

        return null;
    }

    public async Task<string?> GetTsharkVersionAsync(string? customPath = null, CancellationToken cancellationToken = default)
    {
        var tsharkPath = FindTsharkPath(customPath);
        if (string.IsNullOrEmpty(tsharkPath))
        {
            return null;
        }

        var result = await ExecuteAsync(new[] { "--version" }, tsharkPath, TimeSpan.FromSeconds(10), cancellationToken);
        if (!result.IsSuccess || string.IsNullOrWhiteSpace(result.StandardOutput))
        {
            return null;
        }

        using var reader = new StringReader(result.StandardOutput);
        var firstLine = await reader.ReadLineAsync();
        return firstLine?.Trim();
    }

    public async Task<TsharkExecutionResult> ExecuteAsync(
        IEnumerable<string> arguments,
        string? customPath = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        var tsharkPath = FindTsharkPath(customPath);
        if (string.IsNullOrEmpty(tsharkPath))
        {
            return new TsharkExecutionResult
            {
                ExitCode = -1,
                StandardError = "TShark was not found. Install Wireshark or configure the TShark path in Settings."
            };
        }

        var executionTimeout = timeout ?? DefaultExecutionTimeout;
        var result = new TsharkExecutionResult();

        var startInfo = new ProcessStartInfo
        {
            FileName = tsharkPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        foreach (var arg in arguments)
        {
            startInfo.ArgumentList.Add(arg);
        }

        using var process = new Process { StartInfo = startInfo };
        var stdoutBuilder = new StringBuilder();
        var stderrBuilder = new StringBuilder();

        var outputCloseEvent = new TaskCompletionSource<bool>();
        var errorCloseEvent = new TaskCompletionSource<bool>();

        process.OutputDataReceived += (s, e) =>
        {
            if (e.Data == null)
            {
                outputCloseEvent.TrySetResult(true);
            }
            else
            {
                stdoutBuilder.AppendLine(e.Data);
            }
        };

        process.ErrorDataReceived += (s, e) =>
        {
            if (e.Data == null)
            {
                errorCloseEvent.TrySetResult(true);
            }
            else
            {
                stderrBuilder.AppendLine(e.Data);
            }
        };

        try
        {
            if (!process.Start())
            {
                result.StandardError = "Failed to launch TShark process.";
                result.ExitCode = -1;
                return result;
            }

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            using var timeoutCts = new CancellationTokenSource(executionTimeout);
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

            try
            {
                await process.WaitForExitAsync(linkedCts.Token);
                await Task.WhenAll(outputCloseEvent.Task, errorCloseEvent.Task);

                result.ExitCode = process.ExitCode;
                result.StandardOutput = stdoutBuilder.ToString();
                result.StandardError = stderrBuilder.ToString();
            }
            catch (OperationCanceledException)
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                    }
                }
                catch
                {
                    // Suppress process kill errors
                }

                if (cancellationToken.IsCancellationRequested)
                {
                    result.IsCancelled = true;
                    result.StandardError = "Analysis cancelled.";
                }
                else
                {
                    result.IsTimeout = true;
                    result.StandardError = $"TShark execution timed out after {executionTimeout.TotalSeconds:F0} seconds.";
                }
            }
        }
        catch (Exception ex)
        {
            result.ExitCode = -1;
            result.StandardError = $"TShark execution error: {ex.Message}";
        }

        return result;
    }
}
