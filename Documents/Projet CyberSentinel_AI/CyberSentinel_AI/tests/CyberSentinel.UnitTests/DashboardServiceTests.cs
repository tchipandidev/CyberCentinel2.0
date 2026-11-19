using Microsoft.VisualStudio.TestTools.UnitTesting;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.Services;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;

namespace CyberSentinel.UnitTests;

[TestClass]
public class DashboardServiceTests
{
    private class MockScanHistoryRepo : IScanHistoryRepository
    {
        public List<ScanSession> Sessions { get; } = new();

        public Task SaveSessionAsync(ScanSession session, CancellationToken cancellationToken = default)
        {
            Sessions.Add(session);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<ScanSession>> GetRecentSessionsAsync(int maxCount = 20, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<ScanSession>>(Sessions);
        }

        public Task<ScanSession?> GetSessionByIdAsync(Guid sessionId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Sessions.FirstOrDefault(s => s.Id == sessionId));
        }
    }

    private class MockInventoryRepo : IInventoryRepository
    {
        public Task SaveInventorySessionAsync(InventorySession session, CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<IReadOnlyList<InventorySession>> GetInventoryHistoryAsync(int maxCount = 20, CancellationToken cancellationToken = default)
        {
            var list = new List<InventorySession>
            {
                new()
                {
                    TotalApplicationsCount = 42,
                    X64ApplicationsCount = 30,
                    X86ApplicationsCount = 12
                }
            };
            return Task.FromResult<IReadOnlyList<InventorySession>>(list);
        }

        public Task<InventorySession?> GetInventorySessionByIdAsync(Guid sessionId, CancellationToken cancellationToken = default) => Task.FromResult<InventorySession?>(null);
    }

    private class MockUpdateHistoryRepo : IUpdateHistoryRepository
    {
        public Task SaveHistoryEntryAsync(UpdateHistoryRecord record, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<IReadOnlyList<UpdateHistoryRecord>> GetAllHistoryAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<UpdateHistoryRecord>>(new List<UpdateHistoryRecord>());
    }

    [TestMethod]
    public async Task GetDashboardMetricsAsync_CalculatesAggregatedMetricsAccurately()
    {
        var scanRepo = new MockScanHistoryRepo();
        var session1 = new ScanSession
        {
            TargetPath = @"C:\Scan1",
            ScannedFilesCount = 10,
            CleanFilesCount = 9,
            MaliciousFilesCount = 1,
            StartedAt = DateTime.UtcNow.AddHours(-2)
        };
        var session2 = new ScanSession
        {
            TargetPath = @"C:\Scan2",
            ScannedFilesCount = 5,
            CleanFilesCount = 4,
            SuspiciousFilesCount = 1,
            StartedAt = DateTime.UtcNow.AddDays(-2)
        };
        scanRepo.Sessions.Add(session1);
        scanRepo.Sessions.Add(session2);

        var service = new DashboardService(scanRepo, new MockInventoryRepo(), new MockUpdateHistoryRepo());

        // 1. Sans filtre temporel (Tout l'historique)
        var metricsAll = await service.GetDashboardMetricsAsync();
        Assert.AreEqual(15, metricsAll.TotalFilesScanned);
        Assert.AreEqual(1, metricsAll.ThreatsDetectedCount);
        Assert.AreEqual(1, metricsAll.SuspiciousFilesCount);
        Assert.AreEqual(42, metricsAll.TotalInstalledSoftwareCount);
        Assert.IsTrue(metricsAll.OverallSecurityScore < 100.0f, "Le score doit être pénalisé par la présence de menaces.");

        // 2. Avec filtre temporel (Dernières 24h : ignore session2)
        var metrics24h = await service.GetDashboardMetricsAsync(TimeSpan.FromHours(24));
        Assert.AreEqual(10, metrics24h.TotalFilesScanned);
        Assert.AreEqual(1, metrics24h.ThreatsDetectedCount);
        Assert.AreEqual(0, metrics24h.SuspiciousFilesCount);
    }
}

