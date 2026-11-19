using System.Diagnostics;
using System.Security.Principal;
using System.Text.RegularExpressions;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.DTOs;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Application.Services;

/// <summary>
/// Service applicatif de gestion des mises à jour logicielles de CyberSentinel AI.
/// Supervise la détection des versions obsolètes via WinGet, la corrélation avec les vulnérabilités CVE,
/// l'application sécurisée avec confirmation obligatoire et l'audit de traçabilité.
/// </summary>
public class UpdateManagerService : IUpdateManagerService
{
    private readonly ISystemInventoryService _inventoryService;
    private readonly IVulnerabilityProvider _vulnerabilityProvider;
    private readonly IUpdateManager _updateManager;
    private readonly IUpdateHistoryRepository _historyRepository;

    // Regex stricte pour valider les identifiants WinGet officiels (ex: "VideoLAN.VLC", "Google.Chrome")
    private static readonly Regex PackageIdPattern = new(@"^[a-zA-Z0-9\.\-_]{2,100}$", RegexOptions.Compiled);

    public bool IsAdministrator => CheckAdministrativePrivilege();
    public bool IsWinGetAvailable => _updateManager.IsWinGetAvailable;
    public string WinGetVersion => _updateManager.GetWinGetVersion();

    public UpdateManagerService(
        ISystemInventoryService inventoryService,
        IVulnerabilityProvider vulnerabilityProvider,
        IUpdateManager updateManager,
        IUpdateHistoryRepository historyRepository)
    {
        _inventoryService = inventoryService ?? throw new ArgumentNullException(nameof(inventoryService));
        _vulnerabilityProvider = vulnerabilityProvider ?? throw new ArgumentNullException(nameof(vulnerabilityProvider));
        _updateManager = updateManager ?? throw new ArgumentNullException(nameof(updateManager));
        _historyRepository = historyRepository ?? throw new ArgumentNullException(nameof(historyRepository));
    }

    public async Task<IReadOnlyList<SoftwareUpdateDto>> CheckUpdatesAsync(
        IProgress<(string Status, int Percent)>? progress = null, 
        CancellationToken cancellationToken = default)
    {
        progress?.Report(("Étape 1/3 : Inventaire des logiciels installés...", 15));
        var apps = await _inventoryService.GetInstalledApplicationsAsync(cancellationToken);

        progress?.Report(("Étape 2/3 : Recherche des mises à jour disponibles via WinGet...", 45));
        var rawMap = await _updateManager.DiscoverAvailableUpdatesAsync(apps, cancellationToken);
        var updatesMap = new Dictionary<string, SoftwareUpdateInfo>(rawMap, StringComparer.OrdinalIgnoreCase);

        // Si WinGet list direct a aussi trouvé d'autres paquets
        var directUpgrades = await _updateManager.DiscoverAllUpgradesAsync(cancellationToken);
        foreach (var kvp in directUpgrades)
        {
            if (!updatesMap.ContainsKey(kvp.Key))
            {
                updatesMap[kvp.Key] = kvp.Value;
            }
        }

        progress?.Report(("Étape 3/3 : Corrélation avec les correctifs de sécurité critiques CVE...", 75));
        var resultList = new List<SoftwareUpdateDto>();

        int total = apps.Count;
        int index = 0;

        foreach (var app in apps)
        {
            cancellationToken.ThrowIfCancellationRequested();
            index++;

            // Vérifier si une mise à jour est trouvée par ID de package ou nom d'application
            SoftwareUpdateInfo? updateInfo = null;
            if (!string.IsNullOrEmpty(app.PackageIdentifier) && updatesMap.TryGetValue(app.PackageIdentifier, out var infoById))
            {
                updateInfo = infoById;
            }
            else if (updatesMap.TryGetValue(app.DisplayName, out var infoByName))
            {
                updateInfo = infoByName;
            }

            // Vérifier les CVE associées pour prioriser la sécurité
            var vulns = await _vulnerabilityProvider.CheckVulnerabilitiesAsync(app, cancellationToken);
            var criticalVulns = vulns.Where(v => v.Severity >= CvssSeverity.High).ToList();

            var dto = new SoftwareUpdateDto
            {
                Id = updateInfo?.Id ?? Guid.NewGuid(),
                ApplicationName = app.DisplayName,
                PackageIdentifier = updateInfo?.PackageIdentifier ?? (app.PackageIdentifier ?? app.DisplayName),
                CurrentVersion = app.DisplayVersion,
                AvailableVersion = updateInfo?.AvailableVersion ?? (updateInfo != null ? updateInfo.AvailableVersion : app.DisplayVersion),
                SourceRepository = updateInfo?.SourceRepository ?? "winget",
                IsAvailable = updateInfo != null && updateInfo.Status == UpdateStatus.UpdateAvailable,
                HasCriticalSecurityPatch = criticalVulns.Count > 0,
                CVEsAddressed = criticalVulns.Select(v => v.CveId).Distinct().ToList(),
                Status = updateInfo != null ? updateInfo.Status : UpdateStatus.UpToDate,
                StatusMessage = updateInfo != null 
                    ? (criticalVulns.Count > 0 ? $"Correctif critique pour {criticalVulns.Count} CVE(s)" : "Mise à jour disponible")
                    : "Application à jour"
            };

            resultList.Add(dto);
        }

        // Ajouter les paquets WinGet supplémentaires non trouvés dans le registre Windows standard
        foreach (var kvp in directUpgrades)
        {
            if (!resultList.Any(r => string.Equals(r.PackageIdentifier, kvp.Value.PackageIdentifier, StringComparison.OrdinalIgnoreCase)))
            {
                resultList.Add(new SoftwareUpdateDto
                {
                    Id = kvp.Value.Id,
                    ApplicationName = string.IsNullOrEmpty(kvp.Value.ApplicationName) ? kvp.Value.PackageIdentifier : kvp.Value.ApplicationName,
                    PackageIdentifier = kvp.Value.PackageIdentifier,
                    CurrentVersion = kvp.Value.CurrentVersion,
                    AvailableVersion = kvp.Value.AvailableVersion,
                    SourceRepository = kvp.Value.SourceRepository,
                    IsAvailable = true,
                    HasCriticalSecurityPatch = false,
                    Status = UpdateStatus.UpdateAvailable,
                    StatusMessage = "Mise à jour disponible via WinGet"
                });
            }
        }

        progress?.Report(("Analyse des mises à jour terminée.", 100));

        // Trier : Correctifs critiques en premier, puis mises à jour disponibles, puis ordonné par nom
        return resultList
            .OrderByDescending(u => u.HasCriticalSecurityPatch)
            .ThenByDescending(u => u.IsAvailable)
            .ThenBy(u => u.ApplicationName)
            .ToList();
    }

    public async Task<UpdateOperationResultDto> UpgradePackageAsync(
        string packageId, 
        bool isConfirmed, 
        IProgress<string>? consoleOutput = null, 
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();

        // 1. RÈGLE DE SÉCURITÉ : Confirmation explicite obligatoire (Aucun upgrade silencieux non consenti)
        if (!isConfirmed)
        {
            return new UpdateOperationResultDto
            {
                Success = false,
                PackageId = packageId,
                Message = "Sécurité : L'opération de mise à jour a été bloquée car la confirmation utilisateur est obligatoire.",
                RequiresConfirmation = true
            };
        }

        // 2. RÈGLE DE SÉCURITÉ : Validation stricte du format de l'identifiant (prévention de code injection)
        if (string.IsNullOrWhiteSpace(packageId) || !PackageIdPattern.IsMatch(packageId))
        {
            return new UpdateOperationResultDto
            {
                Success = false,
                PackageId = packageId,
                Message = $"Identifiant de package non conforme ou invalide : '{packageId}'.",
                ExitCode = -1
            };
        }

        bool isAdmin = IsAdministrator;
        consoleOutput?.Report($"[CYBERSENTINEL] Initialisation de la mise à jour pour : {packageId}");
        consoleOutput?.Report($"[CYBERSENTINEL] Privilèges Administrateur détectés : {(isAdmin ? "OUI" : "NON (Exécution sous compte standard)")}");

        try
        {
            // 3. Exécution supervisée de la commande WinGet
            var result = await _updateManager.ApplyUpdateAsync(packageId, consoleOutput, cancellationToken);
            stopwatch.Stop();

            var status = result.Success ? UpdateStatus.Updated : UpdateStatus.Failed;
            string message = result.Success 
                ? $"Mise à jour du package '{packageId}' effectuée avec succès." 
                : $"Échec de la mise à jour pour '{packageId}' (Code retour: {result.ExitCode}). {result.ErrorMessage}";

            // 4. RÈGLE DE SÉCURITÉ : Journalisation d'audit de l'opération
            await _historyRepository.SaveHistoryEntryAsync(new UpdateHistoryRecord
            {
                PackageIdentifier = packageId,
                ApplicationName = packageId,
                PreviousVersion = "Audit",
                TargetVersion = "Latest",
                Status = status,
                ExitCode = result.ExitCode,
                Details = message,
                RequiredElevation = !isAdmin,
                Duration = stopwatch.Elapsed
            }, cancellationToken);

            return new UpdateOperationResultDto
            {
                Success = result.Success,
                PackageId = packageId,
                ApplicationName = packageId,
                Message = message,
                ExitCode = result.ExitCode,
                ConsoleOutput = result.Output,
                Duration = stopwatch.Elapsed,
                RequiredElevation = !isAdmin
            };
        }
        catch (OperationCanceledException)
        {
            stopwatch.Stop();
            string msg = $"Opération de mise à jour pour '{packageId}' interrompue par l'utilisateur.";
            consoleOutput?.Report($"[CYBERSENTINEL] {msg}");

            await _historyRepository.SaveHistoryEntryAsync(new UpdateHistoryRecord
            {
                PackageIdentifier = packageId,
                ApplicationName = packageId,
                Status = UpdateStatus.Failed,
                ExitCode = -999,
                Details = msg,
                Duration = stopwatch.Elapsed
            }, CancellationToken.None);

            return new UpdateOperationResultDto
            {
                Success = false,
                PackageId = packageId,
                Message = msg,
                ExitCode = -999,
                Duration = stopwatch.Elapsed
            };
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            string msg = $"Erreur inattendue lors de la mise à jour : {ex.Message}";
            consoleOutput?.Report($"[ERREUR] {msg}");

            return new UpdateOperationResultDto
            {
                Success = false,
                PackageId = packageId,
                Message = msg,
                ExitCode = -1,
                Duration = stopwatch.Elapsed
            };
        }
    }

    public async Task<UpdateOperationResultDto> UpgradeAllAsync(
        bool isConfirmed, 
        IProgress<string>? consoleOutput = null, 
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();

        if (!isConfirmed)
        {
            return new UpdateOperationResultDto
            {
                Success = false,
                PackageId = "ALL",
                Message = "Sécurité : L'application globale de toutes les mises à jour requiert une confirmation explicite.",
                RequiresConfirmation = true
            };
        }

        bool isAdmin = IsAdministrator;
        consoleOutput?.Report("[CYBERSENTINEL] Lancement de la mise à jour globale (winget upgrade --all)...");
        consoleOutput?.Report($"[CYBERSENTINEL] Privilèges Administrateur : {(isAdmin ? "OUI" : "NON")}");

        try
        {
            var result = await _updateManager.ApplyAllUpdatesAsync(consoleOutput, cancellationToken);
            stopwatch.Stop();

            var status = result.Success ? UpdateStatus.Updated : UpdateStatus.Failed;
            string message = result.Success 
                ? "Mise à jour globale de tous les packages exécutée avec succès." 
                : $"La mise à jour globale s'est terminée avec des alertes (Code retour : {result.ExitCode}).";

            await _historyRepository.SaveHistoryEntryAsync(new UpdateHistoryRecord
            {
                PackageIdentifier = "ALL",
                ApplicationName = "Global System Upgrade",
                PreviousVersion = "N/A",
                TargetVersion = "Latest",
                Status = status,
                ExitCode = result.ExitCode,
                Details = message,
                RequiredElevation = !isAdmin,
                Duration = stopwatch.Elapsed
            }, cancellationToken);

            return new UpdateOperationResultDto
            {
                Success = result.Success,
                PackageId = "ALL",
                ApplicationName = "Global System Upgrade",
                Message = message,
                ExitCode = result.ExitCode,
                ConsoleOutput = result.Output,
                Duration = stopwatch.Elapsed,
                RequiredElevation = !isAdmin
            };
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            return new UpdateOperationResultDto
            {
                Success = false,
                PackageId = "ALL",
                Message = $"Échec de la mise à jour globale : {ex.Message}",
                ExitCode = -1,
                Duration = stopwatch.Elapsed
            };
        }
    }

    public async Task<IReadOnlyList<UpdateHistoryRecord>> GetHistoryAsync(CancellationToken cancellationToken = default)
    {
        return await _historyRepository.GetAllHistoryAsync(cancellationToken);
    }

    private static bool CheckAdministrativePrivilege()
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
        catch { }
        return false;
    }
}
