using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Domain.Entities;

/// <summary>
/// Enregistrement d'audit pour chaque opération de mise à jour logicielle effectuée.
/// Conserve l'historique de traçabilité, les versions, le code retour et les privilèges requis.
/// </summary>
public class UpdateHistoryRecord
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    public string PackageIdentifier { get; init; } = string.Empty;
    public string ApplicationName { get; init; } = string.Empty;
    public string PreviousVersion { get; init; } = string.Empty;
    public string TargetVersion { get; init; } = string.Empty;
    public UpdateStatus Status { get; init; } = UpdateStatus.Updated;
    public int ExitCode { get; init; }
    public string Details { get; init; } = string.Empty;
    public bool RequiredElevation { get; init; }
    public bool IsSecurityPatch { get; init; }
    public TimeSpan Duration { get; init; }
}

