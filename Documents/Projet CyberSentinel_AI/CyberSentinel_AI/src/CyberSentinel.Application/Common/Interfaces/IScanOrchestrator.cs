using CyberSentinel.Application.DTOs;
using CyberSentinel.Domain.Entities;

namespace CyberSentinel.Application.Common.Interfaces;

public interface IScanOrchestrator
{
    Task<ScannedFileRecord> ScanSingleFileAsync(
        string filePath, 
        CancellationToken cancellationToken = default);

    Task<ScanSession> ScanDirectoryAsync(
        string directoryPath, 
        bool recursive = true,
        IProgress<ScanProgressDto>? progress = null, 
        CancellationToken cancellationToken = default);
}

