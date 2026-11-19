namespace CyberSentinel.Application.DTOs;

public class DashboardMetricsDto
{
    // État général de la sécurité
    public float OverallSecurityScore { get; set; } = 100.0f;
    public string SecurityPostureVerdict { get; set; } = "Sécurisé";
    public string PostureColor => OverallSecurityScore >= 85.0f 
        ? "#3FB950" 
        : (OverallSecurityScore >= 60.0f ? "#D29922" : "#F85149");

    // Données de malware scanner
    public int TotalFilesScanned { get; set; }
    public int ThreatsDetectedCount { get; set; }
    public int SuspiciousFilesCount { get; set; }
    public int CleanFilesCount { get; set; }

    // Données de vulnérabilités
    public int CriticalVulnerabilitiesCount { get; set; }
    public int HighVulnerabilitiesCount { get; set; }
    public int MediumVulnerabilitiesCount { get; set; }

    // Données de mises à jour
    public int AvailableUpdatesCount { get; set; }
    public int CriticalUpdatesCount { get; set; }
    public int TotalInstalledSoftwareCount { get; set; }

    // Dernier scan
    public DateTime? LastScanDate { get; set; }
    public string LastScanTargetPath { get; set; } = "Aucune analyse récente";
    public string LastScanVerdict { get; set; } = "N/A";
    public long LastScanDurationMs { get; set; }

    public string FormattedLastScanDate => LastScanDate.HasValue 
        ? LastScanDate.Value.ToString("dd/MM/yyyy HH:mm") 
        : "Jamais";

    // Historique récent
    public List<ScanSessionSummaryDto> RecentSessions { get; set; } = new();

    // Ratios pour visualisations graphiques
    public double ThreatPercentage => TotalFilesScanned > 0 
        ? Math.Round((double)ThreatDetectedTotal / TotalFilesScanned * 100, 1) 
        : 0;

    public int ThreatDetectedTotal => ThreatsDetectedCount + SuspiciousFilesCount;
}

