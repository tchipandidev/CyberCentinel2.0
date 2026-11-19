using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Application.DTOs;

public class QuarantineItemDto
{
    public Guid Id { get; set; }
    public string OriginalFilePath { get; set; } = string.Empty;
    public string OriginalFileName { get; set; } = string.Empty;
    public string QuarantinedFilePath { get; set; } = string.Empty;
    public string Sha256Hash { get; set; } = string.Empty;
    public long FileSizeBytes { get; set; }
    public string DetectionReason { get; set; } = string.Empty;
    public QuarantineStatus Status { get; set; }
    public DateTime QuarantinedAt { get; set; }
    public DateTime? RestoredAt { get; set; }
}

