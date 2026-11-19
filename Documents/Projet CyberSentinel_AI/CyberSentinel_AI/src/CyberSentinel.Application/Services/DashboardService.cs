using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.DTOs;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Application.Services;

public class DashboardService : IDashboardService
{
    private readonly IScanHistoryRepository _scanHistoryRepo;
    private readonly IInventoryRepository _inventoryRepo;
    private readonly IUpdateHistoryRepository _updateHistoryRepo;

    public DashboardService(
        IScanHistoryRepository scanHistoryRepo,
        IInventoryRepository inventoryRepo,
        IUpdateHistoryRepository updateHistoryRepo)
    {
        _scanHistoryRepo = scanHistoryRepo ?? throw new ArgumentNullException(nameof(scanHistoryRepo));
        _inventoryRepo = inventoryRepo ?? throw new ArgumentNullException(nameof(inventoryRepo));
        _updateHistoryRepo = updateHistoryRepo ?? throw new ArgumentNullException(nameof(updateHistoryRepo));
    }

    public async Task<DashboardMetricsDto> GetDashboardMetricsAsync(
        TimeSpan? timeWindow = null, 
        CancellationToken cancellationToken = default)
    {
        var allSessions = await _scanHistoryRepo.GetRecentSessionsAsync(100, cancellationToken);
        var now = DateTime.UtcNow;

        var filteredSessions = timeWindow.HasValue
            ? allSessions.Where(s => now - s.StartedAt <= timeWindow.Value).ToList()
            : allSessions.ToList();

        int totalFiles = filteredSessions.Sum(s => s.ScannedFilesCount);
        int malicious = filteredSessions.Sum(s => s.MaliciousFilesCount);
        int suspicious = filteredSessions.Sum(s => s.SuspiciousFilesCount);
        int clean = filteredSessions.Sum(s => s.CleanFilesCount);

        var lastSession = allSessions.OrderByDescending(s => s.StartedAt).FirstOrDefault();

        // Récupération de l'inventaire le plus récent pour compter les logiciels
        int softwareCount = 0;
        try
        {
            var recentInv = await _inventoryRepo.GetInventoryHistoryAsync(1, cancellationToken);
            if (recentInv.Count > 0)
            {
                softwareCount = recentInv[0].TotalApplicationsCount;
            }
        }
        catch { }

        // Calcul dynamique du score de posture globale
        float penalty = (malicious * 30.0f) + (suspicious * 10.0f);
        float score = Math.Max(0.0f, Math.Min(100.0f, 100.0f - penalty));

        string verdict = score >= 85.0f 
            ? "Sécurisé (Posture Optimale)" 
            : (score >= 60.0f ? "Vigilance Requise" : "Risque Critique / Compromission Détectée");

        var metrics = new DashboardMetricsDto
        {
            OverallSecurityScore = (float)Math.Round(score, 1),
            SecurityPostureVerdict = verdict,
            TotalFilesScanned = totalFiles,
            ThreatsDetectedCount = malicious,
            SuspiciousFilesCount = suspicious,
            CleanFilesCount = clean,
            TotalInstalledSoftwareCount = softwareCount,
            LastScanDate = lastSession?.StartedAt,
            LastScanTargetPath = lastSession?.TargetPath ?? "Aucune analyse récente",
            LastScanDurationMs = lastSession?.DurationMs ?? 0,
            LastScanVerdict = lastSession != null 
                ? (lastSession.MaliciousFilesCount > 0 ? "MENACE DÉTECTÉE" : (lastSession.SuspiciousFilesCount > 0 ? "SUSPECT" : "SAIN"))
                : "N/A",
            RecentSessions = allSessions.Take(10).Select(MapToSessionSummary).ToList()
        };

        return metrics;
    }

    private static ScanSessionSummaryDto MapToSessionSummary(ScanSession session)
    {
        return new ScanSessionSummaryDto
        {
            SessionId = session.Id,
            StartedAt = session.StartedAt,
            TargetPath = session.TargetPath,
            ScanType = session.Type,
            Status = session.Status,
            TotalFilesCount = session.ScannedFilesCount,
            MaliciousFilesCount = session.MaliciousFilesCount,
            SuspiciousFilesCount = session.SuspiciousFilesCount,
            CleanFilesCount = session.CleanFilesCount,
            DurationMs = session.DurationMs
        };
    }
}
