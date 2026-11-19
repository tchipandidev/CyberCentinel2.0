using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Domain.Entities;

public class SoftwareUpdateInfo
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public string ApplicationName { get; set; } = string.Empty;
    public string PackageIdentifier { get; init; } = string.Empty;
    public string CurrentVersion { get; init; } = string.Empty;
    public string AvailableVersion { get; init; } = string.Empty;
    public string SourceRepository { get; init; } = "winget";
    public UpdateStatus Status { get; set; } = UpdateStatus.UpdateAvailable;
    public bool HasCriticalSecurityPatch { get; set; }
    public List<string> CVEsAddressed { get; init; } = new();
    public DateTime CheckedAt { get; init; } = DateTime.UtcNow;

    public bool IsNewerVersionAvailable => 
        !string.IsNullOrWhiteSpace(AvailableVersion) && 
        AvailableVersion != CurrentVersion &&
        AvailableVersion != "<";
}
