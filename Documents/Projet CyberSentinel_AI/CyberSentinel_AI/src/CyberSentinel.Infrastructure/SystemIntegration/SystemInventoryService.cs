using System.Runtime.Versioning;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Domain.Entities;

namespace CyberSentinel.Infrastructure.SystemIntegration;

[SupportedOSPlatform("windows")]
public class SystemInventoryService : ISystemInventoryService
{
    private readonly WindowsRegistryScanner _registryScanner;
    private readonly IUpdateManager _updateManager;
    private readonly InventoryReconciliationEngine _reconciliationEngine;

    public SystemInventoryService(
        WindowsRegistryScanner? registryScanner = null,
        IUpdateManager? updateManager = null,
        InventoryReconciliationEngine? reconciliationEngine = null)
    {
        _registryScanner = registryScanner ?? new WindowsRegistryScanner();
        _updateManager = updateManager ?? new WinGetManager();
        _reconciliationEngine = reconciliationEngine ?? new InventoryReconciliationEngine();
    }

    public Task<IReadOnlyList<InstalledApplication>> GetInstalledApplicationsAsync(CancellationToken cancellationToken = default) =>
        GetInstalledApplicationsAsync(null, cancellationToken);

    public async Task<IReadOnlyList<InstalledApplication>> GetInstalledApplicationsAsync(
        IProgress<(string Step, int Percent)>? progress = null, 
        CancellationToken cancellationToken = default)
    {
        // 1. Inventaire des ruches du Registre Windows
        progress?.Report(("Étape 1/3 : Lecture des ruches Uninstall du Registre Windows (64-bit & 32-bit)...", 25));
        var registryApps = await _registryScanner.GetInstalledApplicationsAsync(progress, cancellationToken);

        // 2. Découverte des paquets WinGet
        progress?.Report(("Étape 2/3 : Interrogation du gestionnaire de paquets WinGet...", 60));
        IReadOnlyDictionary<string, SoftwareUpdateInfo>? wingetUpdates = null;
        try
        {
            wingetUpdates = await _updateManager.DiscoverAvailableUpdatesAsync(registryApps, cancellationToken);
        }
        catch
        {
            // Tolérance aux pannes : Si WinGet est indisponible, l'inventaire se poursuit
        }

        // 3. Normalisation, déduplication et réconciliation
        progress?.Report(("Étape 3/3 : Normalisation, déduplication et rapprochement des sources...", 90));
        var reconciledApps = _reconciliationEngine.Reconcile(registryApps, wingetUpdates);

        progress?.Report(($"Inventaire terminé : {reconciledApps.Count} applications uniques identifiées.", 100));

        return reconciledApps;
    }
}
