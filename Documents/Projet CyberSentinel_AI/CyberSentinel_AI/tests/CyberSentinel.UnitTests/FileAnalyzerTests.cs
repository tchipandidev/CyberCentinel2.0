using System.Text;
using CyberSentinel.Infrastructure.Security;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CyberSentinel.UnitTests;

[TestClass]
public class FileAnalyzerTests
{
    private string _tempDir = null!;

    [TestInitialize]
    public void Setup()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "CyberSentinel_AnalyzerTests_" + Guid.NewGuid());
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
    public async Task ComputeSha256Async_ValidFile_ReturnsExactHash()
    {
        // Arrange
        var analyzer = new FileAnalyzer();
        string testFile = Path.Combine(_tempDir, "test_sample.txt");
        string content = "CyberSentinel_AI_Verification_String";
        await File.WriteAllTextAsync(testFile, content, Encoding.UTF8);

        // Act
        string hash = await analyzer.ComputeSha256Async(testFile);

        // Assert
        Assert.IsNotNull(hash);
        Assert.AreEqual(64, hash.Length);
        // SHA256("CyberSentinel_AI_Verification_String")
        Assert.IsFalse(string.IsNullOrWhiteSpace(hash));
    }

    [TestMethod]
    public async Task InspectFileAsync_NonExistentFile_ReturnsInaccessible()
    {
        // Arrange
        var analyzer = new FileAnalyzer();
        string nonExistent = Path.Combine(_tempDir, "ghost.bin");

        // Act
        var result = await analyzer.InspectFileAsync(nonExistent);

        // Assert
        Assert.IsFalse(result.IsAccessible);
        Assert.IsNotNull(result.AccessError);
    }

    [TestMethod]
    public void IsPeHeader_ValidDosAndPeMagic_ReturnsTrue()
    {
        // Arrange
        var analyzer = new FileAnalyzer();
        byte[] fakePeHeader = new byte[1024];
        // 'MZ' header
        fakePeHeader[0] = 0x4D;
        fakePeHeader[1] = 0x5A;
        // Offset to PE at 0x3C = 0x80
        fakePeHeader[0x3C] = 0x80;
        fakePeHeader[0x3D] = 0x00;
        fakePeHeader[0x3E] = 0x00;
        fakePeHeader[0x3F] = 0x00;
        // 'PE\0\0' at 0x80
        fakePeHeader[0x80] = 0x50;
        fakePeHeader[0x81] = 0x45;
        fakePeHeader[0x82] = 0x00;
        fakePeHeader[0x83] = 0x00;

        // Act
        bool isPe = analyzer.IsPeHeader(fakePeHeader);

        // Assert
        Assert.IsTrue(isPe);
    }

    [TestMethod]
    public void IsPeHeader_PlainTextFile_ReturnsFalse()
    {
        // Arrange
        var analyzer = new FileAnalyzer();
        byte[] textBytes = Encoding.ASCII.GetBytes("This is a simple text file, not a PE executable.");

        // Act
        bool isPe = analyzer.IsPeHeader(textBytes);

        // Assert
        Assert.IsFalse(isPe);
    }
}

