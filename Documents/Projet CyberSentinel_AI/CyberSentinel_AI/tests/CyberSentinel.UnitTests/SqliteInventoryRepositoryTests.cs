using Microsoft.VisualStudio.TestTools.UnitTesting;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;
using CyberSentinel.Infrastructure.Persistence;

namespace CyberSentinel.UnitTests;

[TestClass]
public class SqliteInventoryRepositoryTests
{
    private string _testDir = null!;
    private SqliteInventoryRepository _repo = null!;

    [TestInitialize]
    public void Setup()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "CyberSentinel_RepoTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDir);
        _repo = new SqliteInventoryRepository(_testDir);
    }

    [TestCleanup]
    public void Cleanup()
    {
        try
        {
            if (Directory.Exists(_testDir))
            {
                Directory.Delete(_testDir, true);
            }
        }
        catch { }
    }

    [TestMethod]
    public async Task SaveInventorySessionAsync_PersistsSessionAndApplications()
    {
        var session = new InventorySession
        {
            TotalApplicationsCount = 2,
            X64ApplicationsCount = 1,
            X86ApplicationsCount = 1,
            Applications =
            {
                new()
                {
                    DisplayName = "Visual Studio Code",
                    Publisher = "Microsoft Corporation",
                    DisplayVersion = "1.85.1",
                    Architecture = AppArchitecture.X64,
                    PackageIdentifier = "Microsoft.VisualStudioCode",
                    IdentificationSource = "Registry_HKLM_64"
                },
                new()
                {
                    DisplayName = "7-Zip 23.01",
                    Publisher = "Igor Pavlov",
                    DisplayVersion = "23.01",
                    Architecture = AppArchitecture.X86,
                    PackageIdentifier = "7zip.7zip",
                    IdentificationSource = "Registry_HKLM_32"
                }
            }
        };

        await _repo.SaveInventorySessionAsync(session);

        var history = await _repo.GetInventoryHistoryAsync();
        Assert.IsNotNull(history);
        Assert.AreEqual(1, history.Count);
        Assert.AreEqual(2, history[0].TotalApplicationsCount);

        var retrieved = await _repo.GetInventorySessionByIdAsync(session.Id);
        Assert.IsNotNull(retrieved);
        Assert.AreEqual(2, retrieved.Applications.Count);
        Assert.AreEqual("Visual Studio Code", retrieved.Applications[0].DisplayName);

        // Vérification de la création du fichier DDL SQL
        string sqlFile = Path.Combine(_testDir, "inventory_records.sql");
        Assert.IsTrue(File.Exists(sqlFile));
        string sqlContent = await File.ReadAllTextAsync(sqlFile);
        Assert.IsTrue(sqlContent.Contains("INSERT OR REPLACE INTO InventorySessions"));
        Assert.IsTrue(sqlContent.Contains("Visual Studio Code"));
    }
}

