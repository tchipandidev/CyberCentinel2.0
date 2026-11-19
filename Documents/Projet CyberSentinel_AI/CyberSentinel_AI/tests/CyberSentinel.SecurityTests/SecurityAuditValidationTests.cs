using System.Security.Cryptography;
using CyberSentinel.AI.Inference;
using CyberSentinel.Application.Security;
using CyberSentinel.Application.Services;
using CyberSentinel.Domain.Enums;
using CyberSentinel.Infrastructure.Logging;
using CyberSentinel.Infrastructure.Persistence;
using CyberSentinel.Infrastructure.Security;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CyberSentinel.SecurityTests;

[TestClass]
public class SecurityAuditValidationTests
{
    private string _testVaultDir = null!;

    [TestInitialize]
    public void Setup()
    {
        _testVaultDir = Path.Combine(Path.GetTempPath(), $"CyberSentinel_SecTests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testVaultDir);
    }

    [TestCleanup]
    public void Cleanup()
    {
        if (Directory.Exists(_testVaultDir))
        {
            try { Directory.Delete(_testVaultDir, true); } catch { }
        }
    }

    // ------------------------------------------------------------------------
    // 1. INJECTION DE COMMANDES & SANITISATION D'ARGUMENTS
    // ------------------------------------------------------------------------

    [TestMethod]
    public void CommandInjection_MaliciousCharactersInPackageId_BlockedByValidation()
    {
        string[] maliciousPackageIds = 
        {
            "calc.exe & notepad.exe",
            "vlc | powershell -c whoami",
            "curl; rm -rf /",
            "package`whoami`",
            "$(whoami)",
            "app>output.txt",
            "pkg\nmalicious_cmd",
            "pkg\r\ncalc.exe"
        };

        foreach (var badId in maliciousPackageIds)
        {
            bool isValid = System.Text.RegularExpressions.Regex.IsMatch(
                badId, 
                @"^[a-zA-Z0-9\.\-_]{2,100}$");

            Assert.IsFalse(isValid, $"L'identifiant malveillant '{badId}' aurait dû être bloqué par la regex stricte.");
        }
    }

    // ------------------------------------------------------------------------
    // 2. VALIDATION DES CHEMINS & ANTI-PATH TRAVERSAL
    // ------------------------------------------------------------------------

    [TestMethod]
    public void PathTraversal_DosDeviceNames_AreRejected()
    {
        string[] forbiddenDosDevices = { "CON", "PRN", "AUX", "NUL", "COM1", "LPT1" };

        foreach (var dev in forbiddenDosDevices)
        {
            bool safe = PathSecurityValidator.IsPathSafe(dev, out _, out var err);
            Assert.IsFalse(safe, $"Le périphérique réservé {dev} doit être rejeté.");
            Assert.IsNotNull(err);
        }
    }

    [TestMethod]
    public void PathTraversal_NtfsAlternateDataStreams_AreBlocked()
    {
        string adsPath = @"C:\ProgramData\test.txt:stream:$DATA";

        bool safe = PathSecurityValidator.IsPathSafe(adsPath, out _, out var err);

        Assert.IsFalse(safe, "Le flux ADS doit être bloqué.");
        Assert.IsTrue(err!.Contains("flux de données", StringComparison.OrdinalIgnoreCase) || err.Contains("ADS", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void PathTraversal_NullBytes_AreBlocked()
    {
        string nullBytePayload = "test.txt\0.exe";

        bool safe = PathSecurityValidator.IsPathSafe(nullBytePayload, out _, out var err);

        Assert.IsFalse(safe, "L'octet nul doit être rejeté.");
    }

    // ------------------------------------------------------------------------
    // 3. SÉCURITÉ DE LA QUARANTAINE & RESTAURATION ATOMIQUE
    // ------------------------------------------------------------------------

    [TestMethod]
    public async Task Quarantine_Restoration_WhenOriginalPathIsTampered_ThrowsSecurityException()
    {
        var qm = new QuarantineManager(_testVaultDir);

        string sampleFile = Path.Combine(_testVaultDir, "threat.dll");
        await File.WriteAllBytesAsync(sampleFile, new byte[] { 0x4D, 0x5A, 0x90, 0x00 });

        var record = await qm.IsolateFileAsync(sampleFile, "Malware.Trojan.Generic");

        // Falsifier le chemin d'origine avec du path traversal dans les métadonnées
        string metaFile = Path.Combine(_testVaultDir, $"{record.Id}.meta.json");
        string json = await File.ReadAllTextAsync(metaFile);
        string tamperedJson = json.Replace(sampleFile.Replace("\\", "\\\\"), "C:\\\\Windows\\\\System32\\\\cmd.exe");
        await File.WriteAllTextAsync(metaFile, tamperedJson);

        bool securityExceptionThrown = false;
        try
        {
            await qm.RestoreFileAsync(record.Id);
        }
        catch (InvalidOperationException)
        {
            securityExceptionThrown = true;
        }

        Assert.IsTrue(securityExceptionThrown, "La tentative de restauration vers un chemin corrompu doit être interceptée.");
    }

    [TestMethod]
    public async Task Quarantine_Restoration_WhenLockedFileCorrupted_AbortsIntegrityCheck()
    {
        var qm = new QuarantineManager(_testVaultDir);

        string sampleFile = Path.Combine(_testVaultDir, "safe_test.txt");
        await File.WriteAllTextAsync(sampleFile, "CYBERSENTINEL_INTEGRITY_CHECK_DATA");

        var record = await qm.IsolateFileAsync(sampleFile, "Heuristic.Suspicious");

        // Altérer le contenu chiffré
        string lockedFile = Path.Combine(_testVaultDir, $"{record.Id}.locked");
        byte[] lockedBytes = await File.ReadAllBytesAsync(lockedFile);
        lockedBytes[lockedBytes.Length - 1] ^= 0xAA;
        await File.WriteAllBytesAsync(lockedFile, lockedBytes);

        bool integrityFailed = false;
        try
        {
            await qm.RestoreFileAsync(record.Id);
        }
        catch (InvalidOperationException)
        {
            integrityFailed = true;
        }

        Assert.IsTrue(integrityFailed, "L'intégrité SHA-256 altérée doit empêcher la restauration du fichier.");
        Assert.IsFalse(File.Exists(sampleFile), "Le fichier ne doit pas réapparaître sur le disque hôte s'il a été altéré.");
    }

    // ------------------------------------------------------------------------
    // 4. PROTECTION DES MODÈLES IA (ANTI-EMPOISONNEMENT ONNX)
    // ------------------------------------------------------------------------

    [TestMethod]
    public async Task AiModel_Verification_WhenHashMismatch_RejectsModel()
    {
        string modelFile = Path.Combine(_testVaultDir, "poisoned_ember.onnx");
        await File.WriteAllBytesAsync(modelFile, new byte[2048]);

        string trustedOfficialHash = "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0";

        bool isApproved = await OnnxMalwareInferenceService.VerifyModelIntegrityAsync(
            modelFile, 
            CancellationToken.None, 
            expectedSha256: trustedOfficialHash);

        Assert.IsFalse(isApproved, "Le modèle empoisonné avec une empreinte non approuvée doit être rejeté.");
    }

    // ------------------------------------------------------------------------
    // 5. PROTECTION DE LA JOURNALISATION (PII ET SECRETS)
    // ------------------------------------------------------------------------

    [TestMethod]
    public void SecurityLogger_SanitizesSensitiveData()
    {
        string input = "Connexion NVD avec apiKey=secret_api_key_xyz987654 et analyse de C:\\Users\\Administrator\\secret.key";

        string sanitized = SecurityLogger.SanitizeLogContent(input);

        Assert.IsFalse(sanitized.Contains("secret_api_key_xyz987654"));
        Assert.IsFalse(sanitized.Contains("Administrator"));
        Assert.IsTrue(sanitized.Contains("***[REDACTED_SECRET]***"));
        Assert.IsTrue(sanitized.Contains(@"C:\Users\[USER]\"));
    }

    // ------------------------------------------------------------------------
    // 6. PRÉVENTION DES INJECTIONS SQL DANS SQLITE
    // ------------------------------------------------------------------------

    [TestMethod]
    public void Sqlite_EscapeSql_NeutralizesNewlinesAndQuotes()
    {
        string injection = "App'; DELETE FROM InstalledSoftware; --\r\n";

        string escaped = SqliteInventoryRepository.EscapeSql(injection);

        Assert.IsFalse(escaped.Contains("\r"));
        Assert.IsFalse(escaped.Contains("\n"));
        Assert.IsTrue(escaped.Contains("App''; DELETE FROM InstalledSoftware; --"));
    }
}

