using Microsoft.VisualStudio.TestTools.UnitTesting;
using CyberSentinel.Infrastructure.Vulnerabilities;

namespace CyberSentinel.UnitTests;

[TestClass]
public class CpeResolverTests
{
    private CpeResolver _resolver = null!;

    [TestInitialize]
    public void Setup()
    {
        _resolver = new CpeResolver();
    }

    [TestMethod]
    public void Resolve_KnownApplications_ProducesAccurateCpeIdentifiers()
    {
        // VLC media player
        var vlcCpe = _resolver.Resolve("VLC media player", "VideoLAN", "3.0.11");
        Assert.AreEqual("a", vlcCpe.Part);
        Assert.AreEqual("videolan", vlcCpe.Vendor);
        Assert.AreEqual("vlc_media_player", vlcCpe.Product);
        Assert.AreEqual("3.0.11", vlcCpe.Version);
        Assert.AreEqual("cpe:2.3:a:videolan:vlc_media_player:3.0.11:*:*:*:*:*:*:*", vlcCpe.ToCpe23Uri());

        // Google Chrome
        var chromeCpe = _resolver.Resolve("Google Chrome", "Google LLC", "116.0.5845.180");
        Assert.AreEqual("google", chromeCpe.Vendor);
        Assert.AreEqual("chrome", chromeCpe.Product);
        Assert.AreEqual("116.0.5845.180", chromeCpe.Version);

        // 7-Zip
        var sevenZipCpe = _resolver.Resolve("7-Zip 22.01 (x64)", "Igor Pavlov", "22.01");
        Assert.AreEqual("7-zip", sevenZipCpe.Vendor);
        Assert.AreEqual("7-zip", sevenZipCpe.Product);
    }

    [TestMethod]
    public void Resolve_UnknownApplication_FallsBackGracefully()
    {
        var customCpe = _resolver.Resolve("MonLogicielCustom", "MonEntreprise", "1.0.0");
        Assert.AreEqual("a", customCpe.Part);
        Assert.AreEqual("MonEntreprise", customCpe.Vendor);
        Assert.AreEqual("MonLogicielCustom", customCpe.Product);
        Assert.AreEqual("1.0.0", customCpe.Version);
    }
}

