using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Application.DTOs;

public class SoftwareUpdateDto
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string ApplicationName { get; set; } = string.Empty;
    public string PackageIdentifier { get; set; } = string.Empty;
    public string CurrentVersion { get; set; } = string.Empty;
    public string AvailableVersion { get; set; } = string.Empty;
    public string SourceRepository { get; set; } = "winget";
    public bool IsAvailable { get; set; } = true;
    public bool HasCriticalSecurityPatch { get; set; }
    public int CriticalCveCount => CVEsAddressed.Count;
    public List<string> CVEsAddressed { get; set; } = new();
    public UpdateStatus Status { get; set; } = UpdateStatus.UpdateAvailable;
    public string StatusMessage { get; set; } = string.Empty;
    public int ProgressPercent { get; set; }

    public string FormattedVersions => $"{CurrentVersion} ➜ {AvailableVersion}";

    public string StatusBadge => Status switch
    {
        UpdateStatus.Updating => "EN COURS",
        UpdateStatus.Updated => "MIS À JOUR",
        UpdateStatus.Failed => "ÉCHEC",
        UpdateStatus.UpToDate => "À JOUR",
        UpdateStatus.UpdateAvailable when HasCriticalSecurityPatch => "SÉCURITÉ CRITIQUE",
        UpdateStatus.UpdateAvailable => "MISE À JOUR",
        _ => "NON SUPPORTÉ"
    };
}
