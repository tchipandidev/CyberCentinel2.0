using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Domain.Entities;

public class ScanSession
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public ScanType Type { get; init; } = ScanType.SingleFile;
    public string TargetPath { get; init; } = string.Empty;
    public ScanStatus Status { get; set; } = ScanStatus.Pending;
    public DateTime StartedAt { get; init; } = DateTime.UtcNow;
    public DateTime? CompletedAt { get; set; }
    public long DurationMs { get; set; }

    public int TotalFilesCount { get; set; }
    public int ScannedFilesCount { get; set; }
    public int CleanFilesCount { get; set; }
    public int SuspiciousFilesCount { get; set; }
    public int MaliciousFilesCount { get; set; }
    public int ErrorFilesCount { get; set; }

    public List<ScannedFileRecord> Files { get; init; } = new();

    public void RecordFile(ScannedFileRecord file)
    {
        Files.Add(file);
        ScannedFilesCount++;

        switch (file.Verdict)
        {
            case ThreatVerdict.Clean:
                CleanFilesCount++;
                break;
            case ThreatVerdict.Suspicious:
                SuspiciousFilesCount++;
                break;
            case ThreatVerdict.Malicious:
                MaliciousFilesCount++;
                break;
            case ThreatVerdict.Error:
                ErrorFilesCount++;
                break;
        }
    }
}

