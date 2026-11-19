using Microsoft.VisualStudio.TestTools.UnitTesting;
using CyberSentinel.Infrastructure.Vulnerabilities;

namespace CyberSentinel.UnitTests;

[TestClass]
public class VersionRangeMatcherTests
{
    [TestMethod]
    public void IsVulnerable_WhenVersionIsWithinStartIncAndEndExc_ReturnsTrue()
    {
        // 3.0.0 <= 3.0.11 < 3.0.18
        bool vulnerable = VersionRangeMatcher.IsVulnerable(
            installedVersion: "3.0.11",
            versionStartIncluding: "3.0.0",
            versionEndExcluding: "3.0.18");

        Assert.IsTrue(vulnerable, "La version 3.0.11 doit être déclarée vulnérable pour [3.0.0, 3.0.18[.");
    }

    [TestMethod]
    public void IsVulnerable_WhenVersionIsAboveEndExcluding_ReturnsFalse()
    {
        // 3.0.18 is outside [3.0.0, 3.0.18[
        bool vulnerable = VersionRangeMatcher.IsVulnerable(
            installedVersion: "3.0.18",
            versionStartIncluding: "3.0.0",
            versionEndExcluding: "3.0.18");

        Assert.IsFalse(vulnerable, "La version 3.0.18 ne doit pas être vulnérable car borne supérieure exclue.");
    }

    [TestMethod]
    public void IsVulnerable_WhenVersionEqualsEndIncluding_ReturnsTrue()
    {
        // Version <= 22.01 with installed = 22.01
        bool vulnerable = VersionRangeMatcher.IsVulnerable(
            installedVersion: "22.01",
            versionEndIncluding: "22.01");

        Assert.IsTrue(vulnerable, "La version 22.01 doit être vulnérable pour (<= 22.01).");
    }

    [TestMethod]
    public void IsVulnerable_WhenVersionIsHigherThanEndIncluding_ReturnsFalse()
    {
        // Version 23.01 with upper bound <= 22.01
        bool vulnerable = VersionRangeMatcher.IsVulnerable(
            installedVersion: "23.01",
            versionEndIncluding: "22.01");

        Assert.IsFalse(vulnerable, "La version 23.01 doit être saine pour un seuil <= 22.01.");
    }

    [TestMethod]
    public void ParseVersionSegments_ExtractsCorrectIntegerList()
    {
        var segments = VersionRangeMatcher.ParseVersionSegments("116.0.5845.187");

        Assert.AreEqual(4, segments.Count);
        Assert.AreEqual(116, segments[0]);
        Assert.AreEqual(0, segments[1]);
        Assert.AreEqual(5845, segments[2]);
        Assert.AreEqual(187, segments[3]);
    }
}
