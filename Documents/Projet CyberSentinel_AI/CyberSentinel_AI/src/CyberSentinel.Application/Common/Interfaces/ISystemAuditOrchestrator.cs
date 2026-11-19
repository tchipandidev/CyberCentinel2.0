using CyberSentinel.Application.DTOs;

namespace CyberSentinel.Application.Common.Interfaces;

public interface ISystemAuditOrchestrator
{
    Task<(IReadOnlyList<InstalledApplicationDto> Applications, SystemAuditSummaryDto Summary)> RunSystemAuditAsync(
        IProgress<(string Step, int Percent)>? progress = null,
        CancellationToken cancellationToken = default);
}

