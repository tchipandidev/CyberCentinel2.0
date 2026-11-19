using Microsoft.VisualStudio.TestTools.UnitTesting;
using CyberSentinel.AI.Features;

namespace CyberSentinel.UnitTests;

[TestClass]
public class PeFeatureExtractorTests
{
    [TestMethod]
    public void ComputeShannonEntropy_AllZeros_ReturnsZero()
    {
        byte[] zeros = new byte[1024];
        double entropy = PeFeatureExtractor.ComputeShannonEntropy(zeros);

        Assert.AreEqual(0.0, entropy, 0.0001, "L'entropie d'un flux d'octets identiques doit être égale à 0.");
    }

    [TestMethod]
    public void ComputeShannonEntropy_UniformDistribution_ReturnsEightBits()
    {
        // 256 valeurs distinctes équitablement réparties
        byte[] uniform = new byte[256 * 10];
        for (int i = 0; i < uniform.Length; i++)
        {
            uniform[i] = (byte)(i % 256);
        }

        double entropy = PeFeatureExtractor.ComputeShannonEntropy(uniform);

        Assert.AreEqual(8.0, entropy, 0.0001, "L'entropie d'une distribution uniforme de 256 octets doit être égale à 8.0 bits.");
    }

    [TestMethod]
    public async Task ExtractAsync_PlainTextFile_ReturnsInvalidPe()
    {
        string tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, "Ce n'est pas un fichier exécutable binaire.");

            var features = await PeFeatureExtractor.ExtractAsync(tempFile);

            Assert.IsFalse(features.IsValidPe);
            Assert.AreEqual(0, features.NumberOfSections);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }
}

