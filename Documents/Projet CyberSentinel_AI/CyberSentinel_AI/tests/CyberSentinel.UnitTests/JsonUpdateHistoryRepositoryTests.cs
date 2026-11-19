using Microsoft.VisualStudio.TestTools.UnitTesting;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;
using CyberSentinel.Infrastructure.Persistence;

namespace CyberSentinel.UnitTests;

[TestClass]
public class JsonUpdateHistoryRepositoryTests
{
    private string _testDir = null!;
    private JsonUpdateHistoryRepository _repository = null!;

    [TestInitialize]
    public void Setup()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "CyberSentinel_UpdateHistoryTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDir);
        _repository = new JsonUpdateHistoryRepository(_testDir);
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
    public async Task SaveHistoryEntryAsync_StoresAndRetrievesInOrder()
    {
        var entry1 = new UpdateHistoryRecord
        {
            PackageIdentifier = "7zip.7zip",
            ApplicationName = "7-Zip",
            PreviousVersion = "22.01",
            TargetVersion = "23.01",
            Status = UpdateStatus.Updated,
            ExitCode = 0,
            Details = "Mise à jour réussie."
        };

        var entry2 = new UpdateHistoryRecord
        {
            PackageIdentifier = "Google.Chrome",
            ApplicationName = "Google Chrome",
            PreviousVersion = "115.0",
            TargetVersion = "116.0",
            Status = UpdateStatus.Updated,
            ExitCode = 0,
            Details = "Mise à jour réussie."
        };

        await _repository.SaveHistoryEntryAsync(entry1);
        await _repository.SaveHistoryEntryAsync(entry2);

        var list = await _repository.GetAllHistoryAsync();

        Assert.IsNotNull(list);
        Assert.AreEqual(2, list.Count);
        // Le plus récent (entry2) doit être en premier
        Assert.AreEqual("Google.Chrome", list[0].PackageIdentifier);
        Assert.AreEqual("7zip.7zip", list[1].PackageIdentifier);
    }
}

