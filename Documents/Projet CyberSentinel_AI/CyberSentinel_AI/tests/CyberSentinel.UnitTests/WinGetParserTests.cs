using Microsoft.VisualStudio.TestTools.UnitTesting;
using CyberSentinel.Domain.Enums;
using CyberSentinel.Infrastructure.SystemIntegration;

namespace CyberSentinel.UnitTests;

[TestClass]
public class WinGetParserTests
{
    [TestMethod]
    public void ParseWinGetOutput_ParsesStandardTableFormatCorrectly()
    {
        string sampleOutput = 
@"Nom                              ID                     Version        Disponible     Source
--------------------------------------------------------------------------------------------
VideoLAN VLC media player        VideoLAN.VLC           3.0.11         3.0.21         winget
Google Chrome                    Google.Chrome          116.0.5845.180 130.0.6723.117 winget
Notepad++                        Notepad++.Notepad++    8.5.6          8.7.1          winget
Git                              Git.Git                2.42.0         2.42.0         winget
";

        var updates = WinGetManager.ParseWinGetOutput(sampleOutput);

        Assert.IsNotNull(updates);
        // Note: each update is keyed by both ID and Name in WinGetManager
        Assert.IsTrue(updates.ContainsKey("VideoLAN.VLC"), $"VideoLAN.VLC non trouvé dans les clés: [{string.Join(", ", updates.Keys)}]");
        Assert.IsTrue(updates.ContainsKey("Google.Chrome"), "Google.Chrome non trouvé");
        Assert.IsTrue(updates.ContainsKey("Notepad++.Notepad++"), "Notepad++ non trouvé");

        // Git has identical current and available version, should not be included as pending update
        Assert.IsFalse(updates.ContainsKey("Git.Git"));

        var vlc = updates["VideoLAN.VLC"];
        Assert.AreEqual("VideoLAN.VLC", vlc.PackageIdentifier);
        Assert.AreEqual("3.0.11", vlc.CurrentVersion);
        Assert.AreEqual("3.0.21", vlc.AvailableVersion);
        Assert.AreEqual("winget", vlc.SourceRepository);
        Assert.AreEqual(UpdateStatus.UpdateAvailable, vlc.Status);
    }

    [TestMethod]
    public void ParseWinGetOutput_WhenEmptyOrCorrupted_ReturnsEmptyDictionary()
    {
        var emptyResult = WinGetManager.ParseWinGetOutput("");
        Assert.AreEqual(0, emptyResult.Count);

        var corruptedResult = WinGetManager.ParseWinGetOutput("No packages found.");
        Assert.AreEqual(0, corruptedResult.Count);
    }
}
