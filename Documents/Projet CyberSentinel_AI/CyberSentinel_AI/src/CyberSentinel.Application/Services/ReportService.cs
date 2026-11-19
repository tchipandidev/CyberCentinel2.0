using System.Text.Json;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.DTOs;
using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Application.Services;

public class ReportService : IReportService
{
    private readonly IScanHistoryRepository _scanHistoryRepo;
    private readonly IInventoryRepository _inventoryRepo;
    private readonly IVulnerabilityScannerService _vulnService;
    private readonly IUpdateManagerService _updateService;
    private readonly IPdfGenerator _pdfGenerator;

    public ReportService(
        IScanHistoryRepository scanHistoryRepo,
        IInventoryRepository inventoryRepo,
        IVulnerabilityScannerService vulnService,
        IUpdateManagerService updateService,
        IPdfGenerator pdfGenerator)
    {
        _scanHistoryRepo = scanHistoryRepo ?? throw new ArgumentNullException(nameof(scanHistoryRepo));
        _inventoryRepo = inventoryRepo ?? throw new ArgumentNullException(nameof(inventoryRepo));
        _vulnService = vulnService ?? throw new ArgumentNullException(nameof(vulnService));
        _updateService = updateService ?? throw new ArgumentNullException(nameof(updateService));
        _pdfGenerator = pdfGenerator ?? throw new ArgumentNullException(nameof(pdfGenerator));
    }

    public async Task<SecurityReportDto> GenerateFullReportAsync(CancellationToken cancellationToken = default)
    {
        var sessions = await _scanHistoryRepo.GetRecentSessionsAsync(50, cancellationToken);
        var vulns = await _vulnService.ScanVulnerabilitiesAsync(null, cancellationToken);
        var updates = await _updateService.CheckUpdatesAsync(null, cancellationToken);

        int totalFiles = sessions.Sum(s => s.ScannedFilesCount);
        int malicious = sessions.Sum(s => s.MaliciousFilesCount);
        int suspicious = sessions.Sum(s => s.SuspiciousFilesCount);
        int clean = sessions.Sum(s => s.CleanFilesCount);

        int criticalVulns = vulns.Count(v => v.Severity == CvssSeverity.Critical);
        int highVulns = vulns.Count(v => v.Severity == CvssSeverity.High);
        int mediumVulns = vulns.Count(v => v.Severity == CvssSeverity.Medium);

        int pendingUpdates = updates.Count(u => u.IsAvailable);
        int criticalUpdates = updates.Count(u => u.HasCriticalSecurityPatch && u.IsAvailable);

        // Score de posture consolidé
        float penalty = (malicious * 30.0f) + (suspicious * 10.0f) + (criticalVulns * 15.0f) + (highVulns * 8.0f) + (pendingUpdates * 2.0f);
        float score = Math.Max(0.0f, Math.Min(100.0f, 100.0f - penalty));

        string verdict = score >= 85.0f 
            ? "Conforme / Posture Excellente" 
            : (score >= 60.0f ? "Vigilance Requise / Risque Modéré" : "Vulnérable / Risque Critique");

        string summary = $"Audit global consolidé du système ({Environment.MachineName}). " +
                         $"{totalFiles} fichier(s) analysé(s) avec {malicious} menace(s) avérée(s). " +
                         $"{vulns.Count} vulnérabilité(s) CVE détectée(s) dont {criticalVulns} critique(s). " +
                         $"{pendingUpdates} mise(s) à jour logicielle(s) requise(s).";

        var recommendations = new List<string>();
        if (malicious > 0)
        {
            recommendations.Add("Isoler immédiatement les exécutables malveillants identifiés via le Coffre de Quarantaine.");
        }
        if (criticalVulns > 0)
        {
            recommendations.Add($"Déployer en priorité absolue les correctifs pour les {criticalVulns} vulnérabilités de sévérité Critique (CVSS >= 9.0).");
        }
        if (pendingUpdates > 0)
        {
            recommendations.Add($"Appliquer les {pendingUpdates} mises à jour logicielles via WinGet pour résorber la surface d'exposition.");
        }
        if (suspicious > 0)
        {
            recommendations.Add("Effectuer une analyse approfondie et une corrélation YARA/EMBER sur les fichiers suspects détectés.");
        }
        if (recommendations.Count == 0)
        {
            recommendations.Add("Posture de sécurité conforme. Maintenir les scans heuristiques périodiques et la veille NVD.");
        }

        // Extraire les menaces détectées dans les sessions
        var threatList = new List<ScannedFileDto>();
        foreach (var sess in sessions)
        {
            foreach (var f in sess.Files.Where(x => x.Verdict >= ThreatVerdict.Suspicious))
            {
                threatList.Add(new ScannedFileDto
                {
                    FileName = Path.GetFileName(f.FilePath),
                    FilePath = f.FilePath,
                    Sha256Hash = f.Sha256Hash,
                    Verdict = f.Verdict,
                    DetectionSummary = f.EngineResults.FirstOrDefault(e => e.Verdict >= ThreatVerdict.Suspicious)?.ThreatName ?? "Multi-Engine Arbitrator",
                    AnalyzedAt = f.AnalyzedAt
                });
            }
        }

        return new SecurityReportDto
        {
            Title = "CyberSentinel AI - Rapport d'Audit & Posture de Sécurité",
            ExecutiveSummary = summary,
            PostureScore = (float)Math.Round(score, 1),
            PostureVerdict = verdict,
            FilesScanned = totalFiles,
            MaliciousFiles = malicious,
            SuspiciousFiles = suspicious,
            CleanFiles = clean,
            CriticalVulnerabilities = criticalVulns,
            HighVulnerabilities = highVulns,
            MediumVulnerabilities = mediumVulns,
            InstalledSoftwareCount = updates.Count,
            AvailableUpdates = pendingUpdates,
            CriticalSecurityUpdates = criticalUpdates,
            DetectedThreats = threatList.Take(10).ToList(),
            TopVulnerabilities = vulns.Take(10).ToList(),
            PendingUpdates = updates.Where(u => u.IsAvailable).Take(10).ToList(),
            StrategicRecommendations = recommendations
        };
    }

    public async Task<SecurityReportDto> GenerateSessionReportAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        var session = await _scanHistoryRepo.GetSessionByIdAsync(sessionId, cancellationToken);
        if (session == null)
        {
            throw new InvalidOperationException($"La session d'analyse avec l'identifiant '{sessionId}' n'existe pas.");
        }

        var threatList = session.Files.Where(f => f.Verdict >= ThreatVerdict.Suspicious).Select(f => new ScannedFileDto
        {
            FileName = Path.GetFileName(f.FilePath),
            FilePath = f.FilePath,
            Sha256Hash = f.Sha256Hash,
            Verdict = f.Verdict,
            DetectionSummary = f.EngineResults.FirstOrDefault(e => e.Verdict >= ThreatVerdict.Suspicious)?.ThreatName ?? "Verdict Arbitrator",
            AnalyzedAt = f.AnalyzedAt
        }).ToList();

        float score = session.MaliciousFilesCount > 0 ? 30.0f : (session.SuspiciousFilesCount > 0 ? 70.0f : 100.0f);
        string verdict = session.MaliciousFilesCount > 0 ? "Menaces Détectées" : (session.SuspiciousFilesCount > 0 ? "Suspect" : "Sain");

        var recommendations = new List<string>();
        if (session.MaliciousFilesCount > 0)
        {
            recommendations.Add("Mettre en quarantaine les exécutables signalés comme malveillants.");
            recommendations.Add("Vérifier l'origine du binaire et restreindre les privilèges d'exécution.");
        }
        else
        {
            recommendations.Add("Aucune action corrective requise sur le périmètre analysé.");
        }

        return new SecurityReportDto
        {
            Title = $"CyberSentinel AI - Rapport d'Analyse ({session.Type})",
            ExecutiveSummary = $"Analyse de la cible '{session.TargetPath}' effectuée le {session.StartedAt:dd/MM/yyyy HH:mm:ss}. " +
                               $"{session.ScannedFilesCount} fichier(s) audité(s) en {session.DurationMs} ms.",
            PostureScore = score,
            PostureVerdict = verdict,
            FilesScanned = session.ScannedFilesCount,
            MaliciousFiles = session.MaliciousFilesCount,
            SuspiciousFiles = session.SuspiciousFilesCount,
            CleanFiles = session.CleanFilesCount,
            DetectedThreats = threatList,
            StrategicRecommendations = recommendations
        };
    }

    public Task<string> ExportReportToPdfAsync(SecurityReportDto report, string? targetPath = null, CancellationToken cancellationToken = default)
    {
        string exportFile = targetPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            $"CyberSentinel_Security_Report_{DateTime.Now:yyyyMMdd_HHmmss}.pdf");

        string? dir = Path.GetDirectoryName(exportFile);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        using var fs = new FileStream(exportFile, FileMode.Create, FileAccess.Write, FileShare.None);
        _pdfGenerator.GeneratePdf(report, fs);

        return Task.FromResult(exportFile);
    }

    public async Task<string> ExportReportToJsonAsync(SecurityReportDto report, string? targetPath = null, CancellationToken cancellationToken = default)
    {
        string exportFile = targetPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            $"CyberSentinel_Security_Report_{DateTime.Now:yyyyMMdd_HHmmss}.json");

        string? dir = Path.GetDirectoryName(exportFile);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        string json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(exportFile, json, cancellationToken);

        return exportFile;
    }
}
