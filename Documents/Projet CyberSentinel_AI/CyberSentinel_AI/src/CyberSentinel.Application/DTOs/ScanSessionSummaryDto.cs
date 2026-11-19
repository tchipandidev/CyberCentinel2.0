using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Application.DTOs;

public class ScanSessionSummaryDto
{
    public Guid SessionId { get; set; }
    public DateTime StartedAt { get; set; }
    public string TargetPath { get; set; } = string.Empty;
    public ScanType ScanType { get; set; } = ScanType.SingleFile;
    public ScanStatus Status { get; set; } = ScanStatus.Completed;
    public int TotalFilesCount { get; set; }
    public int MaliciousFilesCount { get; set; }
    public int SuspiciousFilesCount { get; set; }
    public int CleanFilesCount { get; set; }
    public long DurationMs { get; set; }

    public string FormattedDate => StartedAt.ToString("dd/MM/yyyy HH:mm:ss");
    public string FormattedDuration => $"{DurationMs} ms";

    public string ScanTypeBadge => ScanType switch
    {
        ScanType.SingleFile => "FICHIER UNIQUE",
        ScanType.Directory => "DOSSIER RÉCURSIF",
        _ => "SYSTÈME"
    };

    public string GlobalVerdictBadge => MaliciousFilesCount > 0 
        ? "MENACES DÉTECTÉES" 
        : (SuspiciousFilesCount > 0 ? "SUSPECT" : "SAIN");

    public string GlobalVerdictColor => MaliciousFilesCount > 0 
        ? "#F85149" 
        : (SuspiciousFilesCount > 0 ? "#D29922" : "#3FB950");
}
