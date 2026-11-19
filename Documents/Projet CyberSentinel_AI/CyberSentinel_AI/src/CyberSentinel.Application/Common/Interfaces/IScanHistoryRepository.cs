using CyberSentinel.Domain.Entities;

namespace CyberSentinel.Application.Common.Interfaces;

public interface IScanHistoryRepository
{
    Task SaveSessionAsync(ScanSession session, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ScanSession>> GetRecentSessionsAsync(int maxCount = 20, CancellationToken cancellationToken = default);
    Task<ScanSession?> GetSessionByIdAsync(Guid sessionId, CancellationToken cancellationToken = default);
}

