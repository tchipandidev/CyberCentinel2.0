using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Application.DTOs;

public class InstalledApplicationDto
{
    public Guid Id { get; set; }
    public string DisplayName { get; set; } = string.Empty;
    public string Publisher { get; set; } = "Éditeur inconnu";
    public string DisplayVersion { get; set; } = "Non spécifiée";
    public AppArchitecture Architecture { get; set; } = AppArchitecture.Unknown;
    public DateTime? InstallDate { get; set; }
    public string InstallLocation { get; set; } = string.Empty;
    public string IdentificationSource { get; set; } = "Registry_HKLM_64";
    public string RegistryHive { get; set; } = string.Empty;
    public string? PackageIdentifier { get; set; }
    public string? CanonicalCpe { get; set; }
    public bool IsSystemComponent { get; set; }

    public string ArchitectureBadge => Architecture switch
    {
        AppArchitecture.X64 => "64-bit",
        AppArchitecture.X86 => "32-bit",
        AppArchitecture.Arm64 => "ARM64",
        AppArchitecture.Neutral => "Any",
        _ => "Inconnue"
    };

    public string FormattedInstallDate => InstallDate.HasValue 
        ? InstallDate.Value.ToString("dd/MM/yyyy") 
        : "Inconnue";

    public bool HasKnownVersion => 
        !string.IsNullOrWhiteSpace(DisplayVersion) && 
        DisplayVersion != "Non spécifiée" && 
        DisplayVersion != "Inconnue";

    public bool HasKnownPublisher => 
        !string.IsNullOrWhiteSpace(Publisher) && 
        Publisher != "Éditeur inconnu" && 
        Publisher != "Unknown";

    public bool HasVulnerabilities => Vulnerabilities.Count > 0;
    public int VulnerabilitiesCount => Vulnerabilities.Count;
    public CvssSeverity HighestSeverity { get; set; }
    public float MaxCvssScore { get; set; }

    public bool HasUpdateAvailable => AvailableUpdate != null && AvailableUpdate.IsAvailable;
    public SoftwareUpdateDto? AvailableUpdate { get; set; }

    public List<VulnerabilityDto> Vulnerabilities { get; set; } = new();
}
