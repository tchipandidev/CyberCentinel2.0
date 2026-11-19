using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Application.DTOs;

public class ScannedFileDto
{
    public Guid Id { get; set; }
    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public string FormattedSize => FormatBytes(FileSizeBytes);
    public string Sha256Hash { get; set; } = string.Empty;
    public bool IsPortableExecutable { get; set; }
    public ThreatVerdict Verdict { get; set; }
    public RiskLevel RiskLevel { get; set; }
    public bool IsInfected => Verdict == ThreatVerdict.Malicious || Verdict == ThreatVerdict.Suspicious;
    public DateTime AnalyzedAt { get; set; }
    public string DetectionSummary { get; set; } = string.Empty;
    public string? ErrorMessage { get; set; }

    public List<ThreatFindingDto> Threats { get; set; } = new();

    private static string FormatBytes(long bytes)
    {
        string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
        int counter = 0;
        decimal number = bytes;
        while (Math.Round(number / 1024) >= 1)
        {
            number /= 1024;
            counter++;
        }
        return $"{number:n1} {suffixes[counter]}";
    }
}

public class ThreatFindingDto
{
    public string EngineName { get; set; } = string.Empty;
    public string ThreatName { get; set; } = string.Empty;
    public RiskLevel RiskLevel { get; set; }
    public string Details { get; set; } = string.Empty;
}
