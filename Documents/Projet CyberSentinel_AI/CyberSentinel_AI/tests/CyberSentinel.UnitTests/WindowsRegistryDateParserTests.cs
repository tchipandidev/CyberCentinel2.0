using Microsoft.VisualStudio.TestTools.UnitTesting;
using CyberSentinel.Infrastructure.SystemIntegration;

namespace CyberSentinel.UnitTests;

[TestClass]
public class WindowsRegistryDateParserTests
{
    [TestMethod]
    public void ParseRegistryInstallDate_StandardYyyyMmDd_ParsesAccurately()
    {
        var dt = WindowsRegistryScanner.ParseRegistryInstallDate("20240915");

        Assert.IsNotNull(dt);
        Assert.AreEqual(2024, dt.Value.Year);
        Assert.AreEqual(9, dt.Value.Month);
        Assert.AreEqual(15, dt.Value.Day);
    }

    [TestMethod]
    public void ParseRegistryInstallDate_NullOrEmptyString_ReturnsNull()
    {
        Assert.IsNull(WindowsRegistryScanner.ParseRegistryInstallDate(null));
        Assert.IsNull(WindowsRegistryScanner.ParseRegistryInstallDate(""));
        Assert.IsNull(WindowsRegistryScanner.ParseRegistryInstallDate("   "));
        Assert.IsNull(WindowsRegistryScanner.ParseRegistryInstallDate("invalid_date_format"));
    }
}

