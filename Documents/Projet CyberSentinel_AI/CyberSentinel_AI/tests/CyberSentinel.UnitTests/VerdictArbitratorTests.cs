using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;
using CyberSentinel.Domain.Rules;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CyberSentinel.UnitTests;

[TestClass]
public class VerdictArbitratorTests
{
    [TestMethod]
    public void Evaluate_ClamAvMaliciousAndYaraClean_ReturnsMaliciousCritical()
    {
        // Arrange
        var results = new List<EngineScanResult>
        {
            EngineScanResult.Success(EngineType.ClamAV, ThreatVerdict.Malicious, RiskLevel.Critical, "Win.Trojan.Agent", "Details", 100),
            EngineScanResult.Success(EngineType.YARA, ThreatVerdict.Clean, RiskLevel.None, null, "Clean", 50)
        };

        // Act
        var (verdict, risk) = VerdictArbitrator.Evaluate(results);

        // Assert
        Assert.AreEqual(ThreatVerdict.Malicious, verdict);
        Assert.AreEqual(RiskLevel.Critical, risk);
    }

    [TestMethod]
    public void Evaluate_YaraCriticalAndClamAvClean_ReturnsMaliciousCritical()
    {
        // Arrange
        var results = new List<EngineScanResult>
        {
            EngineScanResult.Success(EngineType.ClamAV, ThreatVerdict.Clean, RiskLevel.None, null, "Clean", 100),
            EngineScanResult.Success(EngineType.YARA, ThreatVerdict.Malicious, RiskLevel.Critical, "Ransomware_LockBit", "Details", 50)
        };

        // Act
        var (verdict, risk) = VerdictArbitrator.Evaluate(results);

        // Assert
        Assert.AreEqual(ThreatVerdict.Malicious, verdict);
        Assert.AreEqual(RiskLevel.Critical, risk);
    }

    [TestMethod]
    public void Evaluate_YaraSuspiciousAndClamAvClean_ReturnsSuspiciousMedium()
    {
        // Arrange
        var results = new List<EngineScanResult>
        {
            EngineScanResult.Success(EngineType.ClamAV, ThreatVerdict.Clean, RiskLevel.None, null, "Clean", 100),
            EngineScanResult.Success(EngineType.YARA, ThreatVerdict.Suspicious, RiskLevel.Medium, "Suspicious_Strings", "Details", 50)
        };

        // Act
        var (verdict, risk) = VerdictArbitrator.Evaluate(results);

        // Assert
        Assert.AreEqual(ThreatVerdict.Suspicious, verdict);
        Assert.AreEqual(RiskLevel.Medium, risk);
    }

    [TestMethod]
    public void Evaluate_AllEnginesClean_ReturnsCleanNone()
    {
        // Arrange
        var results = new List<EngineScanResult>
        {
            EngineScanResult.Success(EngineType.ClamAV, ThreatVerdict.Clean, RiskLevel.None, null, "Clean", 100),
            EngineScanResult.Success(EngineType.YARA, ThreatVerdict.Clean, RiskLevel.None, null, "Clean", 50)
        };

        // Act
        var (verdict, risk) = VerdictArbitrator.Evaluate(results);

        // Assert
        Assert.AreEqual(ThreatVerdict.Clean, verdict);
        Assert.AreEqual(RiskLevel.None, risk);
    }
}

