using CyberSentinel.Domain.Entities;

namespace CyberSentinel.Application.Common.Interfaces;

public interface IAntivirusScanner
{
    string EngineName { get; }
    Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default);
    Task<EngineScanResult> ScanFileAsync(string filePath, CancellationToken cancellationToken = default);
}

