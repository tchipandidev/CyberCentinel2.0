using Microsoft.VisualStudio.TestTools.UnitTesting;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.Services;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;

namespace CyberSentinel.UnitTests;

[TestClass]
public class UpdateManagerServiceSecurityTests
{
    private class MockInventoryService : ISystemInventoryService
    {
        public Task<IReadOnlyList<InstalledApplication>> GetInstalledApplicationsAsync(
            IProgress<(string Step, int Percent)>? progress = null, 
            CancellationToken cancellationToken = default)
        {
            var apps = new List<InstalledApplication>
            {
                new()
                {
                    DisplayName = "VLC media player",
                    Publisher = "VideoLAN",
                    DisplayVersion = "3.0.11",
                    PackageIdentifier = "VideoLAN.VLC"
                },
                new()
                {
                    DisplayName = "Safe Tool",
                    Publisher = "SafeOrg",
                    DisplayVersion = "1.0.0",
                    PackageIdentifier = "SafeOrg.Tool"
                }
            };
            return Task.FromResult<IReadOnlyList<InstalledApplication>>(apps);
        }

        public Task<IReadOnlyList<InstalledApplication>> GetInstalledApplicationsAsync(CancellationToken cancellationToken = default)
        {
            return GetInstalledApplicationsAsync(null, cancellationToken);
        }
    }

    private class MockVulnerabilityProvider : IVulnerabilityProvider
    {
        public string ProviderName => "MockProvider";

        public Task<IReadOnlyList<VulnerabilityRecord>> CheckVulnerabilitiesAsync(
            InstalledApplication application, 
            CancellationToken cancellationToken = default)
        {
            var list = new List<VulnerabilityRecord>();
            if (application.DisplayName.Contains("VLC", StringComparison.OrdinalIgnoreCase))
            {
                list.Add(new VulnerabilityRecord
                {
                    CveId = "CVE-2022-41325",
                    CvssScore = 7.8f,
                    Severity = CvssSeverity.High,
                    Description = "Heap buffer overflow"
                });
            }
            return Task.FromResult<IReadOnlyList<VulnerabilityRecord>>(list);
        }
    }

    private class MockWinGetManager : IUpdateManager
    {
        public bool IsWinGetAvailable => true;
        public string GetWinGetVersion() => "v1.8.1911";

        public Task<IReadOnlyDictionary<string, SoftwareUpdateInfo>> DiscoverAvailableUpdatesAsync(
            IEnumerable<InstalledApplication> applications, 
            CancellationToken cancellationToken = default)
        {
            var dict = new Dictionary<string, SoftwareUpdateInfo>(StringComparer.OrdinalIgnoreCase)
            {
                ["VideoLAN.VLC"] = new()
                {
                    PackageIdentifier = "VideoLAN.VLC",
                    CurrentVersion = "3.0.11",
                    AvailableVersion = "3.0.21",
                    SourceRepository = "winget",
                    Status = UpdateStatus.UpdateAvailable
                }
            };
            return Task.FromResult<IReadOnlyDictionary<string, SoftwareUpdateInfo>>(dict);
        }

        public Task<IReadOnlyDictionary<string, SoftwareUpdateInfo>> DiscoverAllUpgradesAsync(
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyDictionary<string, SoftwareUpdateInfo>>(new Dictionary<string, SoftwareUpdateInfo>());
        }

        public Task<UpdateExecutionResult> ApplyUpdateAsync(
            string packageIdentifier, 
            IProgress<string>? consoleOutput = null, 
            CancellationToken cancellationToken = default)
        {
            consoleOutput?.Report($"Installing {packageIdentifier}...");
            return Task.FromResult(new UpdateExecutionResult(true, "Successfully installed.", null, 0));
        }

        public Task<UpdateExecutionResult> ApplyAllUpdatesAsync(
            IProgress<string>? consoleOutput = null, 
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new UpdateExecutionResult(true, "All packages upgraded.", null, 0));
        }
    }

    private class MockHistoryRepository : IUpdateHistoryRepository
    {
        public List<UpdateHistoryRecord> SavedEntries { get; } = new();

        public Task SaveHistoryEntryAsync(UpdateHistoryRecord record, CancellationToken cancellationToken = default)
        {
            SavedEntries.Add(record);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<UpdateHistoryRecord>> GetAllHistoryAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<UpdateHistoryRecord>>(SavedEntries);
        }
    }

    [TestMethod]
    public async Task UpgradePackageAsync_WhenNotConfirmed_BlocksExecutionWithSecurityError()
    {
        var history = new MockHistoryRepository();
        var service = new UpdateManagerService(
            new MockInventoryService(), 
            new MockVulnerabilityProvider(), 
            new MockWinGetManager(), 
            history);

        var result = await service.UpgradePackageAsync("VideoLAN.VLC", isConfirmed: false);

        Assert.IsNotNull(result);
        Assert.IsFalse(result.Success, "L'opération non confirmée doit être refusée.");
        Assert.IsTrue(result.RequiresConfirmation, "Le résultat doit indiquer le besoin de confirmation.");
        Assert.AreEqual(0, history.SavedEntries.Count, "Aucune entrée d'exécution ne doit être journalisée sans tentative réelle.");
    }

    [TestMethod]
    public async Task UpgradePackageAsync_WhenInvalidPackageIdFormat_BlocksExecution()
    {
        var history = new MockHistoryRepository();
        var service = new UpdateManagerService(
            new MockInventoryService(), 
            new MockVulnerabilityProvider(), 
            new MockWinGetManager(), 
            history);

        // Injection d'argument / commande suspecte
        var badId = "VideoLAN.VLC; rm -rf /";
        var result = await service.UpgradePackageAsync(badId, isConfirmed: true);

        Assert.IsFalse(result.Success);
        Assert.IsTrue(result.Message.Contains("non conforme") || result.Message.Contains("invalide"));
        Assert.AreEqual(0, history.SavedEntries.Count);
    }

    [TestMethod]
    public async Task UpgradePackageAsync_WhenConfirmedAndValid_ExecutesAndLogsToHistory()
    {
        var history = new MockHistoryRepository();
        var service = new UpdateManagerService(
            new MockInventoryService(), 
            new MockVulnerabilityProvider(), 
            new MockWinGetManager(), 
            history);

        var result = await service.UpgradePackageAsync("VideoLAN.VLC", isConfirmed: true);

        Assert.IsTrue(result.Success);
        Assert.AreEqual(0, result.ExitCode);
        Assert.AreEqual(1, history.SavedEntries.Count, "L'opération doit être auditée et journalisée.");
        
        var record = history.SavedEntries[0];
        Assert.AreEqual("VideoLAN.VLC", record.PackageIdentifier);
        Assert.AreEqual(UpdateStatus.Updated, record.Status);
    }

    [TestMethod]
    public async Task CheckUpdatesAsync_CorrelatesWithCveVulnerabilities()
    {
        var history = new MockHistoryRepository();
        var service = new UpdateManagerService(
            new MockInventoryService(), 
            new MockVulnerabilityProvider(), 
            new MockWinGetManager(), 
            history);

        var updates = await service.CheckUpdatesAsync();

        Assert.IsNotNull(updates);
        var vlc = updates.FirstOrDefault(u => u.PackageIdentifier == "VideoLAN.VLC");
        Assert.IsNotNull(vlc, "VLC doit être présent dans les mises à jour.");
        Assert.IsTrue(vlc.IsAvailable);
        Assert.IsTrue(vlc.HasCriticalSecurityPatch, "VLC doit avoir l'indicateur de sécurité critique activé car CVE-2022-41325 est détectée.");
        Assert.IsTrue(vlc.CVEsAddressed.Contains("CVE-2022-41325"));
    }

    [TestMethod]
    public async Task UpgradeAllAsync_WhenNotConfirmed_RequiresConfirmation()
    {
        var history = new MockHistoryRepository();
        var service = new UpdateManagerService(
            new MockInventoryService(), 
            new MockVulnerabilityProvider(), 
            new MockWinGetManager(), 
            history);

        var result = await service.UpgradeAllAsync(isConfirmed: false);

        Assert.IsFalse(result.Success);
        Assert.IsTrue(result.RequiresConfirmation);
    }
}

