using CyberSentinel.Domain.Entities;

namespace CyberSentinel.Application.Common.Interfaces;

public interface IInventoryRepository
{
    Task SaveInventorySessionAsync(InventorySession session, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<InventorySession>> GetInventoryHistoryAsync(int maxCount = 20, CancellationToken cancellationToken = default);
    Task<InventorySession?> GetInventorySessionByIdAsync(Guid id, CancellationToken cancellationToken = default);
}

