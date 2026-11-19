using CyberSentinel.Domain.Entities;

namespace CyberSentinel.Application.Common.Interfaces;

public interface IYaraScanner
{
    string EngineName { get; }
    int LoadedRulesCount { get; }
    Task<int> LoadRulesFromDirectoryAsync(string directoryPath, CancellationToken cancellationToken = default);
    Task<EngineScanResult> ScanFileAsync(string filePath, CancellationToken cancellationToken = default);
}

