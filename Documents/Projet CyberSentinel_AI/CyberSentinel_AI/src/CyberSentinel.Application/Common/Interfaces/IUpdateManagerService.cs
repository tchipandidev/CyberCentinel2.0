using CyberSentinel.Application.DTOs;
using CyberSentinel.Domain.Entities;

namespace CyberSentinel.Application.Common.Interfaces;

public interface IUpdateManagerService
{
    bool IsAdministrator { get; }
    bool IsWinGetAvailable { get; }
    string WinGetVersion { get; }

    Task<IReadOnlyList<SoftwareUpdateDto>> CheckUpdatesAsync(
        IProgress<(string Status, int Percent)>? progress = null, 
        CancellationToken cancellationToken = default);

    Task<UpdateOperationResultDto> UpgradePackageAsync(
        string packageId, 
        bool isConfirmed, 
        IProgress<string>? consoleOutput = null, 
        CancellationToken cancellationToken = default);

    Task<UpdateOperationResultDto> UpgradeAllAsync(
        bool isConfirmed, 
        IProgress<string>? consoleOutput = null, 
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<UpdateHistoryRecord>> GetHistoryAsync(
        CancellationToken cancellationToken = default);
}

