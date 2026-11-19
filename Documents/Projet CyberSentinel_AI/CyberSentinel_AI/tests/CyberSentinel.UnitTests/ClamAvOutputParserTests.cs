using CyberSentinel.Domain.Enums;
using CyberSentinel.Infrastructure.Security;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CyberSentinel.UnitTests;

[TestClass]
public class ClamAvOutputParserTests
{
    [TestMethod]
    public void ParseOutput_InfectedStdout_ReturnsMaliciousVerdict()
    {
        // Arrange
        string stdout = @"C:\Samples\malware.exe: Win.Trojan.Agent-1234 FOUND";
        string stderr = string.Empty;

        // Act
        var result = ClamAvScanner.ParseOutput(stdout, stderr, exitCode: 1, durationMs: 150);

        // Assert
        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual(ThreatVerdict.Malicious, result.Verdict);
        Assert.AreEqual(RiskLevel.Critical, result.RiskLevel);
        Assert.AreEqual("Win.Trojan.Agent-1234", result.ThreatName);
    }

    [TestMethod]
    public void ParseOutput_CleanStdout_ReturnsCleanVerdict()
    {
        // Arrange
        string stdout = @"C:\Windows\notepad.exe: OK";
        string stderr = string.Empty;

        // Act
        var result = ClamAvScanner.ParseOutput(stdout, stderr, exitCode: 0, durationMs: 80);

        // Assert
        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual(ThreatVerdict.Clean, result.Verdict);
        Assert.AreEqual(RiskLevel.None, result.RiskLevel);
        Assert.IsNull(result.ThreatName);
    }

    [TestMethod]
    public void ParseOutput_ExitCodeZeroWithoutExplicitOk_ReturnsClean()
    {
        // Act
        var result = ClamAvScanner.ParseOutput(string.Empty, string.Empty, exitCode: 0, durationMs: 50);

        // Assert
        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual(ThreatVerdict.Clean, result.Verdict);
    }

    [TestMethod]
    public void ParseOutput_ExitCodeTwo_ReturnsFailure()
    {
        // Arrange
        string stderr = "ERROR: Can't access file";

        // Act
        var result = ClamAvScanner.ParseOutput(string.Empty, stderr, exitCode: 2, durationMs: 30);

        // Assert
        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(ThreatVerdict.Error, result.Verdict);
        Assert.IsTrue(result.ErrorMessage?.Contains("ERROR: Can't access file") ?? false);
    }
}

