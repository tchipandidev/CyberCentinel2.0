using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Domain.Entities;

public class QuarantineRecord
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public string OriginalFilePath { get; init; } = string.Empty;
    public string OriginalFileName { get; init; } = string.Empty;
    public string QuarantinedFileName { get; init; } = string.Empty;
    public string QuarantinedFilePath { get; init; } = string.Empty;
    public string Sha256Hash { get; init; } = string.Empty;
    public long FileSizeBytes { get; init; }
    public string DetectionReason { get; init; } = string.Empty;
    public string EncryptionKeyId { get; init; } = string.Empty;
    public QuarantineStatus Status { get; set; } = QuarantineStatus.Isolated;
    public DateTime QuarantinedAt { get; init; } = DateTime.UtcNow;
    public DateTime? RestoredAt { get; set; }
    public string? Notes { get; set; }
}

