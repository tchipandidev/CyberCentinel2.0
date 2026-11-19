namespace CyberSentinel.Application.DTOs;

public class SecurityReportDto
{
    public Guid ReportId { get; set; } = Guid.NewGuid();
    public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
    public string MachineName { get; set; } = Environment.MachineName;
    public string OperatingSystem { get; set; } = Environment.OSVersion.VersionString;
    public string Title { get; set; } = "CyberSentinel AI - Rapport d'Audit & Posture de Sécurité";
    public string ExecutiveSummary { get; set; } = string.Empty;
    public float PostureScore { get; set; }
    public string PostureVerdict { get; set; } = string.Empty;

    // Statistiques chiffrées
    public int FilesScanned { get; set; }
    public int MaliciousFiles { get; set; }
    public int SuspiciousFiles { get; set; }
    public int CleanFiles { get; set; }
    public int CriticalVulnerabilities { get; set; }
    public int HighVulnerabilities { get; set; }
    public int MediumVulnerabilities { get; set; }
    public int InstalledSoftwareCount { get; set; }
    public int AvailableUpdates { get; set; }
    public int CriticalSecurityUpdates { get; set; }

    // Listes détaillées
    public List<ScannedFileDto> DetectedThreats { get; set; } = new();
    public List<VulnerabilityDto> TopVulnerabilities { get; set; } = new();
    public List<SoftwareUpdateDto> PendingUpdates { get; set; } = new();
    public List<string> StrategicRecommendations { get; set; } = new();

    public string FormattedDate => GeneratedAt.ToString("dd/MM/yyyy HH:mm:ss");
}

