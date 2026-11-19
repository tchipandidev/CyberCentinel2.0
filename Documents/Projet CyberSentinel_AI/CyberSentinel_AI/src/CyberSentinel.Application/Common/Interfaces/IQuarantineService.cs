using CyberSentinel.Domain.Entities;

namespace CyberSentinel.Application.Common.Interfaces;

public interface IQuarantineService
{
    string VaultDirectoryPath { get; }
    Task<QuarantineRecord> IsolateFileAsync(string sourceFilePath, string detectionReason, CancellationToken cancellationToken = default);
    Task<bool> RestoreFileAsync(Guid quarantineId, CancellationToken cancellationToken = default);
    Task<bool> PurgeFileAsync(Guid quarantineId, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<QuarantineRecord>> GetAllQuarantinedItemsAsync(CancellationToken cancellationToken = default);
}

