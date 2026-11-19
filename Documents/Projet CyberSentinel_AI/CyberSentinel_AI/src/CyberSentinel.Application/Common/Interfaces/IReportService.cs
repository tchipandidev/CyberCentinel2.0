using CyberSentinel.Application.DTOs;

namespace CyberSentinel.Application.Common.Interfaces;

public interface IReportService
{
    Task<SecurityReportDto> GenerateFullReportAsync(
        CancellationToken cancellationToken = default);

    Task<SecurityReportDto> GenerateSessionReportAsync(
        Guid sessionId, 
        CancellationToken cancellationToken = default);

    Task<string> ExportReportToPdfAsync(
        SecurityReportDto report, 
        string? targetPath = null, 
        CancellationToken cancellationToken = default);

    Task<string> ExportReportToJsonAsync(
        SecurityReportDto report, 
        string? targetPath = null, 
        CancellationToken cancellationToken = default);
}

