using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Domain.Entities;

public class InstalledApplication
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public string DisplayName { get; init; } = string.Empty;
    public string Publisher { get; init; } = "Éditeur inconnu";
    public string DisplayVersion { get; init; } = "Non spécifiée";
    public AppArchitecture Architecture { get; init; } = AppArchitecture.Unknown;
    public DateTime? InstallDate { get; init; }
    public string InstallLocation { get; init; } = string.Empty;
    public string IdentificationSource { get; init; } = "Registry_HKLM_64";
    public string RegistryHive { get; init; } = string.Empty;
    public string? PackageIdentifier { get; set; }
    public string? CanonicalCpe { get; set; }
    public string? UninstallString { get; init; }
    public bool IsSystemComponent { get; init; }
    public DateTime DiscoveredAt { get; init; } = DateTime.UtcNow;

    public List<VulnerabilityRecord> Vulnerabilities { get; init; } = new();
    public SoftwareUpdateInfo? AvailableUpdate { get; set; }

    public bool HasKnownVersion => 
        !string.IsNullOrWhiteSpace(DisplayVersion) && 
        DisplayVersion != "Non spécifiée" && 
        DisplayVersion != "Inconnue";

    public bool HasKnownPublisher => 
        !string.IsNullOrWhiteSpace(Publisher) && 
        Publisher != "Éditeur inconnu" && 
        Publisher != "Unknown";

    public CvssSeverity HighestSeverity => Vulnerabilities.Count > 0 
        ? Vulnerabilities.Max(v => v.Severity) 
        : CvssSeverity.None;

    public float MaxCvssScore => Vulnerabilities.Count > 0 
        ? Vulnerabilities.Max(v => v.CvssScore) 
        : 0.0f;
}
