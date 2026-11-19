using Microsoft.VisualStudio.TestTools.UnitTesting;
using CyberSentinel.AI.Classification;
using CyberSentinel.Domain.Enums;

namespace CyberSentinel.UnitTests;

[TestClass]
public class EmberAiClassifierTests
{
    private EmberAiClassifier _classifier = null!;

    [TestInitialize]
    public void Setup()
    {
        _classifier = new EmberAiClassifier();
    }

    [TestMethod]
    public async Task ClassifyPeFileAsync_NonPeFile_ReturnsCleanVerdictBypassed()
    {
        string tempTextFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempTextFile, "CyberSentinel non-pe document");

            var result = await _classifier.ClassifyPeFileAsync(tempTextFile);

            Assert.IsTrue(result.IsSuccess);
            Assert.AreEqual(EngineType.EMBER_AI, result.Engine);
            Assert.AreEqual(ThreatVerdict.Clean, result.Verdict);
            Assert.AreEqual(RiskLevel.None, result.RiskLevel);
            Assert.IsTrue(result.Details.Contains("Fichier non-PE"));
        }
        finally
        {
            if (File.Exists(tempTextFile)) File.Delete(tempTextFile);
        }
    }

    [TestMethod]
    public async Task ClassifyPeFileAsync_NonExistentFile_ReturnsFailure()
    {
        var result = await _classifier.ClassifyPeFileAsync(@"C:\NonExistent_FakePath_12345.exe");

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(ThreatVerdict.Error, result.Verdict);
    }
}

