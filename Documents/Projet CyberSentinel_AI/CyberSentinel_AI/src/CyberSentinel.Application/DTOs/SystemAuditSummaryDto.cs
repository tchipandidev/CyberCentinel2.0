using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Application.DTOs;

public class SystemAuditSummaryDto
{
    public DateTime AuditDate { get; set; } = DateTime.UtcNow;
    public int TotalInstalledSoftware { get; set; }
    public int VulnerableSoftwareCount { get; set; }
    public int TotalCvesFound { get; set; }
    public int CriticalCvesCount { get; set; }
    public int HighCvesCount { get; set; }
    public int MediumCvesCount { get; set; }
    public int LowCvesCount { get; set; }
    public int UpdatesAvailableCount { get; set; }
    public int SecurityUpdatesCount { get; set; }
    public float GlobalExposureScore { get; set; } // 0 (Worst) to 100 (Safe)
    public string PostureVerdict { get; set; } = "Sécurisé";
}

