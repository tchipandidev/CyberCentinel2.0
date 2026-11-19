using System.Text.RegularExpressions;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Infrastructure.Logging;

public class SecurityLogger : ISecurityLogger
{
    private readonly string _logDirectory;
    private readonly object _syncLock = new();
    private static readonly Regex ApiKeyPattern = new(@"((?:api[_-]?key|token|secret|password)[\s:=]+)([a-zA-Z0-9_\-\.]{6,})", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex UserPathPattern = new(@"([a-zA-Z]:\\Users\\)([^\\]+)(\\)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public string LogDirectory => _logDirectory;

    public SecurityLogger(string? customLogDir = null)
    {
        _logDirectory = customLogDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            @"CyberSentinel\Logs");

        if (!Directory.Exists(_logDirectory))
        {
            Directory.CreateDirectory(_logDirectory);
        }
    }

    public void LogInformation(string source, string message) =>
        Log(SecurityLogLevel.Information, source, message);

    public void LogWarning(string source, string message) =>
        Log(SecurityLogLevel.Warning, source, message);

    public void LogError(string source, string message, Exception? exception = null) =>
        Log(SecurityLogLevel.Error, source, message, exception);

    public void LogCritical(string source, string message, Exception? exception = null) =>
        Log(SecurityLogLevel.Critical, source, message, exception);

    public void Log(SecurityLogLevel level, string source, string message, Exception? exception = null)
    {
        string timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff UTC");
        string sanitizedMsg = SanitizeLogContent(message);
        string levelBadge = level.ToString().ToUpperInvariant().PadRight(11);

        string logLine = $"[{timestamp}] [{levelBadge}] [{source}] {sanitizedMsg}";

        if (exception != null)
        {
            string sanitizedException = SanitizeLogContent(exception.ToString());
            logLine += Environment.NewLine + "  [EXCEPTION] " + sanitizedException;
        }

        string todayFileName = $"security_audit_{DateTime.UtcNow:yyyyMMdd}.log";
        string filePath = Path.Combine(_logDirectory, todayFileName);

        lock (_syncLock)
        {
            try
            {
                File.AppendAllText(filePath, logLine + Environment.NewLine);
            }
            catch
            {
                // Éviter de propager les erreurs d'E/S du logger pour préserver le fonctionnement métier
            }
        }
    }

    public Task FlushAsync(CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    public async Task<IReadOnlyList<string>> GetRecentLogsAsync(int maxCount = 100, CancellationToken cancellationToken = default)
    {
        string todayFileName = $"security_audit_{DateTime.UtcNow:yyyyMMdd}.log";
        string filePath = Path.Combine(_logDirectory, todayFileName);

        if (!File.Exists(filePath))
        {
            return Array.Empty<string>();
        }

        try
        {
            var lines = await File.ReadAllLinesAsync(filePath, cancellationToken);
            return lines.Reverse().Take(maxCount).ToList();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    public static string SanitizeLogContent(string? content)
    {
        if (string.IsNullOrEmpty(content)) return string.Empty;

        // 1. Masquage des jetons et clés secrètes d'API
        string sanitized = ApiKeyPattern.Replace(content, m => $"{m.Groups[1].Value}***[REDACTED_SECRET]***");

        // 2. Masquage des identifiants utilisateurs dans les chemins de fichiers (Protection PII RGPD / NIST)
        sanitized = UserPathPattern.Replace(sanitized, m => $"{m.Groups[1].Value}[USER]{m.Groups[3].Value}");

        return sanitized;
    }
}

