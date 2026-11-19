using System.Security.Cryptography;
using System.Text;
using CyberSentinel.Domain.Enums;
using CyberSentinel.Infrastructure.Security;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CyberSentinel.UnitTests;

[TestClass]
public class QuarantineManagerTests
{
    private string _tempDir = null!;
    private string _vaultDir = null!;

    [TestInitialize]
    public void Setup()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "CyberSentinel_QTests_" + Guid.NewGuid());
        _vaultDir = Path.Combine(_tempDir, "Vault");
        Directory.CreateDirectory(_tempDir);
        Directory.CreateDirectory(_vaultDir);
    }

    [TestCleanup]
    public void Cleanup()
    {
        if (Directory.Exists(_tempDir))
        {
            try { Directory.Delete(_tempDir, true); } catch { }
        }
    }

    [TestMethod]
    public async Task IsolateFileAsync_ValidFile_QuarantinesAndRemovesOriginal()
    {
        // Arrange
        var manager = new QuarantineManager(_vaultDir);
        string sampleFile = Path.Combine(_tempDir, "malware_sample.exe");
        string originalContent = "MZ_MALWARE_DUMMY_BINARY_PAYLOAD_TEST";
        await File.WriteAllTextAsync(sampleFile, originalContent, Encoding.UTF8);

        // Act
        var record = await manager.IsolateFileAsync(sampleFile, "Detection ClamAV: Test.Trojan");

        // Assert
        Assert.IsNotNull(record);
        Assert.AreEqual(QuarantineStatus.Isolated, record.Status);
        Assert.IsFalse(File.Exists(sampleFile), "Le fichier original doit être supprimé après isolation.");
        Assert.IsTrue(File.Exists(record.QuarantinedFilePath), "Le fichier chiffré doit exister dans le coffre.");

        // Vérifier que le fichier est altéré (ne contient plus le texte original en clair)
        string lockedBytes = await File.ReadAllTextAsync(record.QuarantinedFilePath);
        Assert.AreNotEqual(originalContent, lockedBytes, "Le contenu dans le coffre doit être chiffré/masqué.");
    }

    [TestMethod]
    public async Task RestoreFileAsync_QuarantinedFile_RestoresOriginalContentAndHash()
    {
        // Arrange
        var manager = new QuarantineManager(_vaultDir);
        string sampleFile = Path.Combine(_tempDir, "restore_test.bin");
        string originalContent = "Critical_Document_Restoration_Integrity_Check";
        await File.WriteAllTextAsync(sampleFile, originalContent, Encoding.UTF8);

        string originalHash;
        using (var sha = SHA256.Create())
        using (var stream = File.OpenRead(sampleFile))
        {
            originalHash = Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
        }

        var record = await manager.IsolateFileAsync(sampleFile, "Test Isolation");
        Assert.IsFalse(File.Exists(sampleFile));

        // Act
        bool restored = await manager.RestoreFileAsync(record.Id);

        // Assert
        Assert.IsTrue(restored, "La restauration doit réussir.");
        Assert.IsTrue(File.Exists(sampleFile), "Le fichier d'origine doit être reconstitué.");

        string restoredContent = await File.ReadAllTextAsync(sampleFile, Encoding.UTF8);
        Assert.AreEqual(originalContent, restoredContent);

        string restoredHash;
        using (var sha = SHA256.Create())
        using (var stream = File.OpenRead(sampleFile))
        {
            restoredHash = Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
        }

        Assert.AreEqual(originalHash, restoredHash, "L'empreinte SHA-256 du fichier restauré doit correspondre exactement.");
    }

    [TestMethod]
    public async Task PurgeFileAsync_QuarantinedFile_SecurelyOverwritesAndDeletes()
    {
        // Arrange
        var manager = new QuarantineManager(_vaultDir);
        string sampleFile = Path.Combine(_tempDir, "to_purge.exe");
        await File.WriteAllTextAsync(sampleFile, "PAYLOAD_TO_BE_PURGED", Encoding.UTF8);

        var record = await manager.IsolateFileAsync(sampleFile, "Purge Test");
        Assert.IsTrue(File.Exists(record.QuarantinedFilePath));

        // Act
        bool purged = await manager.PurgeFileAsync(record.Id);

        // Assert
        Assert.IsTrue(purged);
        Assert.IsFalse(File.Exists(record.QuarantinedFilePath), "Le fichier dans le coffre doit être supprimé.");
    }
}

