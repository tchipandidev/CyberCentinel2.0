using Microsoft.VisualStudio.TestTools.UnitTesting;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;
using CyberSentinel.Infrastructure.SystemIntegration;

namespace CyberSentinel.UnitTests;

[TestClass]
public class InventoryReconciliationTests
{
    private InventoryReconciliationEngine _engine = null!;

    [TestInitialize]
    public void Setup()
    {
        _engine = new InventoryReconciliationEngine();
    }

    [TestMethod]
    public void Reconcile_DeduplicatesSameApplicationAcrossHives()
    {
        var regApps = new List<InstalledApplication>
        {
            new()
            {
                DisplayName = "Google Chrome",
                Publisher = "Google LLC",
                DisplayVersion = "120.0.6099.110",
                Architecture = AppArchitecture.X64,
                IdentificationSource = "Registry_HKLM_64"
            },
            new()
            {
                DisplayName = "Google Chrome (x64)",
                Publisher = "Google LLC",
                DisplayVersion = "120.0.6099.110",
                Architecture = AppArchitecture.X64,
                IdentificationSource = "Registry_HKCU"
            }
        };

        var reconciled = _engine.Reconcile(regApps);

        Assert.AreEqual(1, reconciled.Count, "Les deux entrées de Google Chrome doivent être fusionnées en une seule.");
        Assert.AreEqual("Google Chrome", reconciled[0].DisplayName);
        Assert.IsTrue(reconciled[0].IdentificationSource.Contains("Registry_HKLM_64"));
    }

    [TestMethod]
    public void Reconcile_EnrichesApplicationWithWinGetIdentifier()
    {
        var regApps = new List<InstalledApplication>
        {
            new()
            {
                DisplayName = "VideoLAN VLC media player",
                Publisher = "VideoLAN",
                DisplayVersion = "3.0.18",
                Architecture = AppArchitecture.X64,
                IdentificationSource = "Registry_HKLM_64"
            }
        };

        var wingetUpdates = new Dictionary<string, SoftwareUpdateInfo>
        {
            ["VideoLAN VLC media player"] = new()
            {
                PackageIdentifier = "VideoLAN.VLC",
                CurrentVersion = "3.0.18",
                AvailableVersion = "3.0.21",
                Status = UpdateStatus.UpdateAvailable
            }
        };

        var reconciled = _engine.Reconcile(regApps, wingetUpdates);

        Assert.AreEqual(1, reconciled.Count);
        Assert.AreEqual("VideoLAN.VLC", reconciled[0].PackageIdentifier);
        Assert.IsNotNull(reconciled[0].AvailableUpdate);
        Assert.AreEqual("3.0.21", reconciled[0].AvailableUpdate!.AvailableVersion);
    }

    [TestMethod]
    public void NormalizeApplicationName_StripsArchitectureSuffixesCorrectly()
    {
        string norm1 = InventoryReconciliationEngine.NormalizeApplicationName("Notepad++ (64-bit)");
        Assert.AreEqual("Notepad++", norm1);

        string norm2 = InventoryReconciliationEngine.NormalizeApplicationName("Git (x64)");
        Assert.AreEqual("Git", norm2);

        string norm3 = InventoryReconciliationEngine.NormalizeApplicationName("7-Zip (32-bit)");
        Assert.AreEqual("7-Zip", norm3);
    }
}

