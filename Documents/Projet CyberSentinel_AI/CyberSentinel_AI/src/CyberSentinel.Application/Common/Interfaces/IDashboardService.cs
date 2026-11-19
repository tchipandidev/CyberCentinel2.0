using CyberSentinel.Application.DTOs;

namespace CyberSentinel.Application.Common.Interfaces;

public interface IDashboardService
{
    Task<DashboardMetricsDto> GetDashboardMetricsAsync(
        TimeSpan? timeWindow = null, 
        CancellationToken cancellationToken = default);
}

