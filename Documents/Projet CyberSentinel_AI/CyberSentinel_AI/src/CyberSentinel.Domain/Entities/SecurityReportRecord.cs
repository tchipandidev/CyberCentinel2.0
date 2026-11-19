namespace CyberSentinel.Domain.Entities;

/// <summary>
/// Entité métier représentant un rapport consolidé de sécurité généré pour un audit système complet.
/// </summary>
public class SecurityReportRecord
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public DateTime GeneratedAt { get; init; } = DateTime.UtcNow;
    public string Title { get; init; } = "CyberSentinel AI - Rapport Consolidé de Sécurité";
    public string TargetMachine { get; init; } = Environment.MachineName;
    public string OperatingSystem { get; init; } = Environment.OSVersion.VersionString;
    public string ExecutiveSummary { get; set; } = string.Empty;
    public float SecurityPostureScore { get; set; }
    public string SecurityPostureVerdict { get; set; } = string.Empty;

    // Métriques globales
    public int TotalFilesScanned { get; set; }
    public int MaliciousThreatsCount { get; set; }
    public int SuspiciousThreatsCount { get; set; }
    public int CleanFilesCount { get; set; }
    public int CriticalVulnerabilitiesCount { get; set; }
    public int HighVulnerabilitiesCount { get; set; }
    public int MediumVulnerabilitiesCount { get; set; }
    public int TotalInstalledSoftwareCount { get; set; }
    public int PendingUpdatesCount { get; set; }
    public int CriticalSecurityUpdatesCount { get; set; }

    // Recommandations
    public List<string> Recommendations { get; init; } = new();

    // Détails
    public List<ScannedFileRecord> TopThreats { get; init; } = new();
    public List<VulnerabilityRecord> TopVulnerabilities { get; init; } = new();
    public List<SoftwareUpdateInfo> PendingSecurityUpdates { get; init; } = new();
}

