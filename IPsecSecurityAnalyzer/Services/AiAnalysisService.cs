using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Runs the bundled Python AI engine using the Python interpreter configured in Settings.
/// The service never relies on a developer-machine working directory.
/// </summary>
public class AiAnalysisService : IAiAnalysisService
{
    private const string AiModule = "ai_engine.infer";
    private static readonly TimeSpan InferenceTimeout = TimeSpan.FromSeconds(60);

    private readonly ISettingsService _settingsService;

    public AiAnalysisService() : this(new SettingsService())
    {
    }

    public AiAnalysisService(ISettingsService settingsService)
    {
        _settingsService = settingsService;
    }

    public async Task<AiAnalysisResult> GetAiAnalysisAsync(IEnumerable<object>? packets = null)
    {
        try
        {
            var workingDirectory = ResolveAiWorkingDirectory();
            if (workingDirectory == null)
            {
                return Failure("The bundled ai_engine folder could not be found. Rebuild the application so the ai_engine folder is copied to the output directory.");
            }

            var pythonPath = ResolvePythonExecutable();
            if (pythonPath == null)
            {
                return Failure("Python was not found. Configure the Python executable in Settings (for example: C:\\Users\\<user>\\AppData\\Local\\Python\\pythoncore-3.14-64\\python.exe).");
            }

            var payload = JsonSerializer.Serialize(new { packets = packets ?? Array.Empty<object>() });
            var startInfo = new ProcessStartInfo
            {
                FileName = pythonPath,
                WorkingDirectory = workingDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            startInfo.ArgumentList.Add("-m");
            startInfo.ArgumentList.Add(AiModule);

            using var process = new Process { StartInfo = startInfo };
            if (!process.Start())
            {
                return Failure($"Could not start Python: {pythonPath}");
            }

            await process.StandardInput.WriteAsync(payload);
            await process.StandardInput.FlushAsync();
            process.StandardInput.Close();

            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();

            using var timeoutCts = new CancellationTokenSource(InferenceTimeout);
            try
            {
                await process.WaitForExitAsync(timeoutCts.Token);
            }
            catch (OperationCanceledException)
            {
                try { if (!process.HasExited) process.Kill(true); } catch { }
                return Failure("Python AI inference timed out after 60 seconds.");
            }

            var stdout = await stdoutTask;
            var stderr = await stderrTask;

            if (process.ExitCode != 0)
            {
                var details = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
                return Failure($"Python AI inference failed (exit code {process.ExitCode}). {details.Trim()}");
            }

            if (string.IsNullOrWhiteSpace(stdout))
            {
                return Failure("Python AI engine returned no output.");
            }

            var result = JsonSerializer.Deserialize<AiAnalysisResult>(stdout, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (result == null)
            {
                return Failure("Python AI engine returned invalid JSON.");
            }

            if (!result.IsModelConnected)
            {
                return Failure(result.ErrorMessage ?? "Python AI engine reported that the model is unavailable.");
            }

            result.ErrorMessage = null;
            result.IsModelConnected = true;
            return result;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[AiAnalysisService] {ex}");
            return Failure(ex.Message);
        }
    }

    private string? ResolvePythonExecutable()
    {
        var configured = _settingsService.Settings?.PythonPath;
        if (!string.IsNullOrWhiteSpace(configured))
        {
            var trimmed = configured.Trim('"', '\'', ' ');
            if (File.Exists(trimmed) && Path.GetFileNameWithoutExtension(trimmed).Equals("python", StringComparison.OrdinalIgnoreCase))
                return Path.GetFullPath(trimmed);

            if (Directory.Exists(trimmed))
            {
                foreach (var candidate in new[] { "python.exe", "python" })
                {
                    var path = Path.Combine(trimmed, candidate);
                    if (File.Exists(path)) return Path.GetFullPath(path);
                }
            }
        }

        var candidates = new[]
        {
            Environment.GetEnvironmentVariable("Python_ROOT_DIR"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Python", "pythoncore-3.14-64", "python.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Python", "Python313", "python.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Python", "Python312", "python.exe")
        };

        foreach (var candidate in candidates.Where(p => !string.IsNullOrWhiteSpace(p)))
        {
            if (File.Exists(candidate!)) return Path.GetFullPath(candidate!);
        }

        return FindExecutableOnPath("python.exe") ?? FindExecutableOnPath("python");
    }

    private static string? FindExecutableOnPath(string executable)
    {
        var pathEnv = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(pathEnv)) return null;

        foreach (var entry in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var candidate = Path.Combine(entry.Trim(), executable);
                if (File.Exists(candidate)) return Path.GetFullPath(candidate);
            }
            catch { }
        }
        return null;
    }

    private static string? ResolveAiWorkingDirectory()
    {
        var candidates = new List<string>
        {
            AppContext.BaseDirectory,
            Directory.GetCurrentDirectory()
        };

        foreach (var start in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var directory = new DirectoryInfo(start);
            while (directory != null)
            {
                var aiFolder = Path.Combine(directory.FullName, "ai_engine");
                var inferFile = Path.Combine(aiFolder, "infer.py");
                if (Directory.Exists(aiFolder) && File.Exists(inferFile))
                    return directory.FullName;
                directory = directory.Parent;
            }
        }

        return null;
    }

    private static AiAnalysisResult Failure(string message) => new()
    {
        IsModelConnected = false,
        ErrorMessage = message,
        Features = new Dictionary<string, string>(),
        Anomalies = new List<string>(),
        TopFeatures = new List<FeatureImportance>()
    };
}
