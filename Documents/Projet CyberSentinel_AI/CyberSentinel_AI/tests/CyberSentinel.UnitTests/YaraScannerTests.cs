using System.Text;
using CyberSentinel.Domain.Enums;
using CyberSentinel.Infrastructure.Security;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CyberSentinel.UnitTests;

[TestClass]
public class YaraScannerTests
{
    private string _tempDir = null!;

    [TestInitialize]
    public void Setup()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "CyberSentinel_YaraTests_" + Guid.NewGuid());
        Directory.CreateDirectory(_tempDir);
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
    public async Task ScanFileAsync_RansomwareNote_DetectsMalware()
    {
        // Arrange
        var scanner = new YaraScanner();
        string testFile = Path.Combine(_tempDir, "ransom_instruction.txt");
        string content = "Attention! All your files have been encrypted by ransomware. Pay the ransom to recover your files.";
        await File.WriteAllTextAsync(testFile, content, Encoding.UTF8);

        // Act
        var result = await scanner.ScanFileAsync(testFile);

        // Assert
        Assert.IsTrue(result.IsSuccess, $"L'analyse YARA a échoué: {result.Details}");
        Assert.AreEqual(ThreatVerdict.Malicious, result.Verdict);
        Assert.AreEqual(RiskLevel.High, result.RiskLevel);
        Assert.AreEqual("Ransomware_Payment_Note", result.ThreatName);
    }

    [TestMethod]
    public async Task ScanFileAsync_BenignTextFile_ReturnsClean()
    {
        // Arrange
        var scanner = new YaraScanner();
        string testFile = Path.Combine(_tempDir, "clean.txt");
        await File.WriteAllTextAsync(testFile, "Hello world, this is a clean file without any signatures.", Encoding.UTF8);

        // Act
        var result = await scanner.ScanFileAsync(testFile);

        // Assert
        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual(ThreatVerdict.Clean, result.Verdict);
        Assert.AreEqual(RiskLevel.None, result.RiskLevel);
    }

    [TestMethod]
    public async Task ScanFileAsync_PartialProcessInjectionAPIs_DoesNotFalsePositive()
    {
        // Arrange: only one API present out of the 3 required
        var scanner = new YaraScanner();
        string testFile = Path.Combine(_tempDir, "benign_tool.txt");
        await File.WriteAllTextAsync(testFile, "This tool only references VirtualAllocEx for legitimate local memory.", Encoding.ASCII);

        // Act
        var result = await scanner.ScanFileAsync(testFile);

        // Assert: Multi-pattern rule requires all 3 APIs to avoid false positive!
        Assert.AreEqual(ThreatVerdict.Clean, result.Verdict);
    }

    [TestMethod]
    public async Task ScanFileAsync_FullProcessInjectionAPIs_DetectsHighThreat()
    {
        // Arrange: All 3 APIs present
        var scanner = new YaraScanner();
        string testFile = Path.Combine(_tempDir, "injector.bin");
        string content = "Payload with VirtualAllocEx and WriteProcessMemory and CreateRemoteThread to hook explorer.exe";
        await File.WriteAllTextAsync(testFile, content, Encoding.ASCII);

        // Act
        var result = await scanner.ScanFileAsync(testFile);

        // Assert
        Assert.AreEqual(ThreatVerdict.Malicious, result.Verdict);
        Assert.AreEqual(RiskLevel.High, result.RiskLevel);
        Assert.AreEqual("Process_Injection_Heuristic", result.ThreatName);
    }
}

