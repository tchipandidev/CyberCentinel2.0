using CyberSentinel.Domain.Entities;

namespace CyberSentinel.Application.Common.Interfaces;

public interface ISystemInventoryService
{
    Task<IReadOnlyList<InstalledApplication>> GetInstalledApplicationsAsync(CancellationToken cancellationToken = default);
    
    Task<IReadOnlyList<InstalledApplication>> GetInstalledApplicationsAsync(
        IProgress<(string Step, int Percent)>? progress,
        CancellationToken cancellationToken = default);
}
