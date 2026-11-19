using CyberSentinel.Domain.Entities;

namespace CyberSentinel.Application.Common.Interfaces;

public interface IUpdateHistoryRepository
{
    Task SaveHistoryEntryAsync(UpdateHistoryRecord record, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<UpdateHistoryRecord>> GetAllHistoryAsync(CancellationToken cancellationToken = default);
}

