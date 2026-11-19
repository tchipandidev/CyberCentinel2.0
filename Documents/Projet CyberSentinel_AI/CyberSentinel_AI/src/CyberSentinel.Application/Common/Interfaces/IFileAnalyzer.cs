namespace CyberSentinel.Application.Common.Interfaces;

public record FileInspectionResult(
    string FilePath,
    string FileName,
    long FileSizeBytes,
    string Sha256Hash,
    bool IsPortableExecutable,
    bool IsAccessible,
    string? AccessError = null
);

public interface IFileAnalyzer
{
    Task<FileInspectionResult> InspectFileAsync(string filePath, CancellationToken cancellationToken = default);
    Task<string> ComputeSha256Async(string filePath, CancellationToken cancellationToken = default);
    bool IsPeHeader(byte[] headerBytes);
}

