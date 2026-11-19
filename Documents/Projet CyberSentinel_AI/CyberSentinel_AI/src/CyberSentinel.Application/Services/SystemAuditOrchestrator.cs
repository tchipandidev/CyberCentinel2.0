using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.DTOs;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Application.Services;

public class SystemAuditOrchestrator : ISystemAuditOrchestrator
{
    private readonly ISystemInventoryService _inventoryService;
    private readonly IVulnerabilityProvider _vulnerabilityProvider;
    private readonly IUpdateManager _updateManager;

    public SystemAuditOrchestrator(
        ISystemInventoryService inventoryService,
        IVulnerabilityProvider vulnerabilityProvider,
        IUpdateManager updateManager)
    {
        _inventoryService = inventoryService;
        _vulnerabilityProvider = vulnerabilityProvider;
        _updateManager = updateManager;
    }

    public async Task<(IReadOnlyList<InstalledApplicationDto> Applications, SystemAuditSummaryDto Summary)> RunSystemAuditAsync(
        IProgress<(string Step, int Percent)>? progress = null,
        CancellationToken cancellationToken = default)
    {
        // Étape 1 : Inventaire des logiciels installés (Registre Windows)
        progress?.Report(("Étape 1/3 : Inventaire des logiciels installés...", 15));
        var installedApps = (await _inventoryService.GetInstalledApplicationsAsync(cancellationToken)).ToList();

        // Étape 2 : Découverte des mises à jour WinGet disponibles
        progress?.Report(("Étape 2/3 : Vérification des mises à jour logicielles...", 45));
        var updatesMap = await _updateManager.DiscoverAvailableUpdatesAsync(installedApps, cancellationToken);

        foreach (var app in installedApps)
        {
            if (!string.IsNullOrEmpty(app.PackageIdentifier) && updatesMap.TryGetValue(app.PackageIdentifier, out var updateInfo))
            {
                app.AvailableUpdate = updateInfo;
            }
            else if (updatesMap.TryGetValue(app.DisplayName, out var updateByName))
            {
                app.AvailableUpdate = updateByName;
            }
        }

        // Étape 3 : Requêtage et corrélation des vulnérabilités CVE
        progress?.Report(("Étape 3/3 : Corrélation des vulnérabilités CVE (NVD/OSV)...", 75));
        int totalApps = installedApps.Count;
        int checkedCount = 0;

        foreach (var app in installedApps)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var vulns = await _vulnerabilityProvider.CheckVulnerabilitiesAsync(app, cancellationToken);
            app.Vulnerabilities.AddRange(vulns);

            // Règle RG-004 : Priorisation des correctifs de sécurité critiques
            if (app.AvailableUpdate != null && vulns.Any(v => v.Severity >= CvssSeverity.High))
            {
                app.AvailableUpdate.HasCriticalSecurityPatch = true;
            }

            checkedCount++;
            int progressPercent = 75 + (int)((double)checkedCount / totalApps * 20);
            progress?.Report(($"Audit vulnérabilités ({checkedCount}/{totalApps}) : {app.DisplayName}", progressPercent));
        }

        // Étape 4 : Calcul du bilan et de la posture globale
        progress?.Report(("Finalisation de l'audit système...", 100));

        var dtos = installedApps.Select(MapToDto).OrderByDescending(a => a.MaxCvssScore).ThenByDescending(a => a.HasUpdateAvailable).ToList();
        var summary = CalculateSummary(installedApps);

        return (dtos, summary);
    }

    private static InstalledApplicationDto MapToDto(InstalledApplication app)
    {
        return new InstalledApplicationDto
        {
            Id = app.Id,
            DisplayName = app.DisplayName,
            Publisher = app.Publisher,
            DisplayVersion = app.DisplayVersion,
            InstallLocation = app.InstallLocation,
            RegistryHive = app.RegistryHive,
            PackageIdentifier = app.PackageIdentifier,
            CanonicalCpe = app.CanonicalCpe,
            HighestSeverity = app.HighestSeverity,
            MaxCvssScore = app.MaxCvssScore,
            AvailableUpdate = app.AvailableUpdate != null ? new SoftwareUpdateDto
            {
                Id = app.AvailableUpdate.Id,
                ApplicationName = app.DisplayName,
                PackageIdentifier = app.AvailableUpdate.PackageIdentifier,
                CurrentVersion = app.AvailableUpdate.CurrentVersion,
                AvailableVersion = app.AvailableUpdate.AvailableVersion,
                SourceRepository = app.AvailableUpdate.SourceRepository,
                IsAvailable = app.AvailableUpdate.Status == UpdateStatus.UpdateAvailable,
                HasCriticalSecurityPatch = app.AvailableUpdate.HasCriticalSecurityPatch,
                Status = app.AvailableUpdate.Status,
                StatusMessage = app.AvailableUpdate.HasCriticalSecurityPatch ? "Correctif de sécurité critique !" : "Mise à jour disponible"
            } : null,
            Vulnerabilities = app.Vulnerabilities.Select(v => new VulnerabilityDto
            {
                Id = v.Id,
                CveId = v.CveId,
                AffectedSoftware = app.DisplayName,
                InstalledVersion = app.DisplayVersion,
                Description = v.Description,
                CvssScore = v.CvssScore,
                Severity = v.Severity,
                VectorString = v.VectorString,
                VulnerableRange = v.VulnerableVersionRange,
                MatchStatus = v.MatchStatus,
                PublishedAt = v.PublishedAt,
                ReferenceUrl = v.ReferenceUrl,
                RemediationRecommendation = v.RemediationRecommendation,
                PatchedVersion = v.PatchedVersion,
                SourceProvider = v.SourceProvider,
                IsRemediated = v.IsRemediated
            }).ToList()
        };
    }

    private static SystemAuditSummaryDto CalculateSummary(List<InstalledApplication> apps)
    {
        int totalApps = apps.Count;
        var vulnerableApps = apps.Where(a => a.Vulnerabilities.Count > 0).ToList();
        var allCves = apps.SelectMany(a => a.Vulnerabilities).ToList();
        var updates = apps.Where(a => a.AvailableUpdate != null && a.AvailableUpdate.Status == UpdateStatus.UpdateAvailable).ToList();

        int critical = allCves.Count(v => v.Severity == CvssSeverity.Critical);
        int high = allCves.Count(v => v.Severity == CvssSeverity.High);
        int medium = allCves.Count(v => v.Severity == CvssSeverity.Medium);
        int low = allCves.Count(v => v.Severity == CvssSeverity.Low);

        // Score de posture : Démarre à 100, pénalisé par la sévérité des CVEs et des MAJ manquantes
        float penalty = (critical * 25.0f) + (high * 12.0f) + (medium * 4.0f) + (low * 1.0f) + (updates.Count * 2.0f);
        float score = Math.Max(0.0f, Math.Min(100.0f, 100.0f - penalty));

        string verdict = score >= 85 ? "Sécurisé" : (score >= 60 ? "Vigilance Requise" : "Vulnérable / Risque Élevé");

        return new SystemAuditSummaryDto
        {
            AuditDate = DateTime.UtcNow,
            TotalInstalledSoftware = totalApps,
            VulnerableSoftwareCount = vulnerableApps.Count,
            TotalCvesFound = allCves.Count,
            CriticalCvesCount = critical,
            HighCvesCount = high,
            MediumCvesCount = medium,
            LowCvesCount = low,
            UpdatesAvailableCount = updates.Count,
            SecurityUpdatesCount = updates.Count(u => u.AvailableUpdate!.HasCriticalSecurityPatch),
            GlobalExposureScore = (float)Math.Round(score, 1),
            PostureVerdict = verdict
        };
    }
}
