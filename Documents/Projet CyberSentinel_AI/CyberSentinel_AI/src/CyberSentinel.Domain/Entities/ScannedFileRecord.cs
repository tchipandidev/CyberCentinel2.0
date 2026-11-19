using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Domain.Entities;

public class ScannedFileRecord
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid? SessionId { get; set; }
    public string FilePath { get; init; } = string.Empty;
    public string FileName { get; init; } = string.Empty;
    public long FileSizeBytes { get; init; }
    public string Sha256Hash { get; set; } = string.Empty;
    public bool IsPortableExecutable { get; set; }
    public ThreatVerdict Verdict { get; set; } = ThreatVerdict.Clean;
    public RiskLevel RiskLevel { get; set; } = RiskLevel.None;
    public DateTime AnalyzedAt { get; init; } = DateTime.UtcNow;
    public string? ErrorMessage { get; set; }

    public List<ThreatFinding> Threats { get; init; } = new();
    public List<EngineScanResult> EngineResults { get; init; } = new();

    public bool IsInfected => Verdict == ThreatVerdict.Malicious || Verdict == ThreatVerdict.Suspicious;
}

