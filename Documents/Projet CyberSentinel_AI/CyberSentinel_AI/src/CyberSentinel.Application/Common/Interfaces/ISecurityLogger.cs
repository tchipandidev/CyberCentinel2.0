using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Application.Common.Interfaces;

/// <summary>
/// Contrat d'interface pour le journal d'audit de sécurité applicatif.
/// Prend en charge la catégorisation stricte des événements, le masquage des données sensibles (PII / tokens),
/// et la persistance traçable des opérations d'administration et d'analyse.
/// </summary>
public interface ISecurityLogger
{
    void Log(SecurityLogLevel level, string source, string message, Exception? exception = null);
    void LogInformation(string source, string message);
    void LogWarning(string source, string message);
    void LogError(string source, string message, Exception? exception = null);
    void LogCritical(string source, string message, Exception? exception = null);

    Task FlushAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<string>> GetRecentLogsAsync(int maxCount = 100, CancellationToken cancellationToken = default);
}

