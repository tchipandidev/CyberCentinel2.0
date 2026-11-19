using CyberSentinel.Domain.Entities;

namespace CyberSentinel.Application.Common.Interfaces;

public record UpdateExecutionResult(
    bool Success, 
    string Output, 
    string? ErrorMessage = null, 
    int ExitCode = 0
);

public interface IUpdateManager
{
    bool IsWinGetAvailable { get; }
    string GetWinGetVersion();

    Task<IReadOnlyDictionary<string, SoftwareUpdateInfo>> DiscoverAvailableUpdatesAsync(
        IEnumerable<InstalledApplication> applications, 
        CancellationToken cancellationToken = default);

    Task<IReadOnlyDictionary<string, SoftwareUpdateInfo>> DiscoverAllUpgradesAsync(
        CancellationToken cancellationToken = default);

    Task<UpdateExecutionResult> ApplyUpdateAsync(
        string packageIdentifier, 
        IProgress<string>? consoleOutput = null, 
        CancellationToken cancellationToken = default);

    Task<UpdateExecutionResult> ApplyAllUpdatesAsync(
        IProgress<string>? consoleOutput = null, 
        CancellationToken cancellationToken = default);
}
