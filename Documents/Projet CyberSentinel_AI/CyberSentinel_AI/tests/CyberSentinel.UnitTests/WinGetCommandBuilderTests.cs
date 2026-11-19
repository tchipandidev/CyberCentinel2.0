using Microsoft.VisualStudio.TestTools.UnitTesting;
using CyberSentinel.Infrastructure.SystemIntegration;

namespace CyberSentinel.UnitTests;

[TestClass]
public class WinGetCommandBuilderTests
{
    [TestMethod]
    public void MapWinGetExitCode_StandardExitCodes_ReturnsClearFrenchExplanations()
    {
        string success = WinGetManager.MapWinGetExitCode(0);
        Assert.IsTrue(success.Contains("succès"));

        string noUpdates = WinGetManager.MapWinGetExitCode(unchecked((int)0x8A150011));
        Assert.IsTrue(noUpdates.Contains("Aucune mise à jour applicable"));

        string alreadyInstalled = WinGetManager.MapWinGetExitCode(unchecked((int)0x8A150005));
        Assert.IsTrue(alreadyInstalled.Contains("déjà installé"));

        string elevationRequired = WinGetManager.MapWinGetExitCode(unchecked((int)0x8A15002B));
        Assert.IsTrue(elevationRequired.Contains("Administrateur") || elevationRequired.Contains("privilèges"));

        string accessDenied = WinGetManager.MapWinGetExitCode(unchecked((int)0x80070005));
        Assert.IsTrue(accessDenied.Contains("Accès refusé"));
    }

    [TestMethod]
    public void ParseWinGetOutput_WithEnglishHeaders_ParsesCorrectly()
    {
        string englishOutput = 
@"Name                             Id                     Version        Available      Source
--------------------------------------------------------------------------------------------
Mozilla Firefox                  Mozilla.Firefox        118.0.1        120.0.1        winget
Git                              Git.Git                2.40.0         2.45.1         winget
";

        var parsed = WinGetManager.ParseWinGetOutput(englishOutput);

        Assert.IsNotNull(parsed);
        Assert.IsTrue(parsed.ContainsKey("Mozilla.Firefox"));
        Assert.IsTrue(parsed.ContainsKey("Git.Git"));

        var firefox = parsed["Mozilla.Firefox"];
        Assert.AreEqual("118.0.1", firefox.CurrentVersion);
        Assert.AreEqual("120.0.1", firefox.AvailableVersion);
    }
}

