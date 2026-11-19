using System.Security.Cryptography;
using CyberSentinel.AI.Inference;
using CyberSentinel.Application.Security;
using CyberSentinel.Domain.Enums;
using CyberSentinel.Infrastructure.Logging;
using CyberSentinel.Infrastructure.Persistence;
using CyberSentinel.Infrastructure.Security;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CyberSentinel.UnitTests;

[TestClass]
public class ApplicationSecurityAuditTests
{
    private string _testVaultDir = null!;

    [TestInitialize]
    public void Setup()
    {
        _testVaultDir = Path.Combine(Path.GetTempPath(), $"CyberSentinel_SecAudit_{Guid.NewGuid():N}");
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

    // -------------------------------------------------------------
    // 1. TESTS DE SÉCURITÉ : VALIDATION DES CHEMINS & ANTI-PATH TRAVERSAL
    // -------------------------------------------------------------

    [TestMethod]
    public void PathSecurityValidator_WhenDosDeviceNameConOrNul_BlocksAccess()
    {
        // Périphériques DOS réservés (peuvent figer le thread I/O sous Windows)
        string[] dangerousPaths = { "CON", "NUL", "AUX", "PRN", @"C:\temp\CON.txt", @"C:\temp\NUL\file.bin" };

        foreach (var path in dangerousPaths)
        {
            bool isSafe = PathSecurityValidator.IsPathSafe(path, out var sanitized, out var error);
            Assert.IsFalse(isSafe, $"Le chemin réservé DOS '{path}' aurait dû être bloqué.");
            Assert.IsNotNull(error);
        }
    }

    [TestMethod]
    public void PathSecurityValidator_WhenAlternateDataStream_BlocksAccess()
    {
        // Tentative d'accès à un flux ADS NTFS illicite
        string adsPath = @"C:\Users\Public\file.txt:hidden_payload.exe";

        bool isSafe = PathSecurityValidator.IsPathSafe(adsPath, out _, out var error);

        Assert.IsFalse(isSafe, "L'accès à un flux ADS NTFS aurait dû être bloqué.");
        Assert.IsTrue(error!.Contains("NTFS ADS", StringComparison.OrdinalIgnoreCase) || error.Contains("flux de données", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void PathSecurityValidator_WhenNullByteInjected_BlocksAccess()
    {
        string nullBytePayload = "C:\\Windows\\System32\\calc.exe\0.txt";

        bool isSafe = PathSecurityValidator.IsPathSafe(nullBytePayload, out _, out var error);

        Assert.IsFalse(isSafe, "L'injection d'un octet nul aurait dû être rejetée.");
        Assert.IsTrue(error!.Contains("octets nuls", StringComparison.OrdinalIgnoreCase));
    }

    [TestMethod]
    public void PathSecurityValidator_WhenValidWindowsPath_Passes()
    {
        string validPath = @"C:\Program Files\CyberSentinel\app.exe";

        bool isSafe = PathSecurityValidator.IsPathSafe(validPath, out var sanitized, out var error);

        Assert.IsTrue(isSafe);
        Assert.IsNull(error);
        Assert.IsNotNull(sanitized);
    }

    [TestMethod]
    public void PathSecurityValidator_IsWithinAllowedRoot_DetectsTraversalEscape()
    {
        string rootDir = @"C:\CyberSentinel\SafeVault";
        string escapingPath = @"C:\CyberSentinel\SafeVault\..\..\Windows\System32\cmd.exe";

        bool isWithin = PathSecurityValidator.IsWithinAllowedRoot(escapingPath, rootDir);

        Assert.IsFalse(isWithin, "Une tentative de remontée par '..' hors de la racine doit retourner false.");
    }

    // -------------------------------------------------------------
    // 2. TESTS DE SÉCURITÉ : QUARANTAINE & RESTAURATION ATOMIQUE
    // -------------------------------------------------------------

    [TestMethod]
    public async Task QuarantineManager_RestoreFileAsync_WhenOriginalPathTamperedWithTraversal_RejectsAndThrows()
    {
        var quarantineMgr = new QuarantineManager(_testVaultDir);

        // Créer un fichier test
        string tempSource = Path.Combine(_testVaultDir, "threat_sample.bin");
        await File.WriteAllBytesAsync(tempSource, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });

        var record = await quarantineMgr.IsolateFileAsync(tempSource, "Test.Detection.Threat");

        // Falsifier le chemin de restauration dans les métadonnées (Attaque Path Traversal via meta.json)
        string metaPath = Path.Combine(_testVaultDir, $"{record.Id}.meta.json");
        string tamperedJson = (await File.ReadAllTextAsync(metaPath))
            .Replace(tempSource.Replace("\\", "\\\\"), "C:\\\\Windows\\\\System32\\\\CON.txt");
        await File.WriteAllTextAsync(metaPath, tamperedJson);

        // La restauration doit rejeter ce chemin non sécurisé
        bool threwException = false;
        try
        {
            await quarantineMgr.RestoreFileAsync(record.Id);
        }
        catch (InvalidOperationException)
        {
            threwException = true;
        }

        Assert.IsTrue(threwException, "La restauration vers un chemin corrompu/traversal doit lever une exception de sécurité.");
    }

    [TestMethod]
    public async Task QuarantineManager_RestoreFileAsync_WhenLockedFileTampered_AbortsIntegrityCheck()
    {
        var quarantineMgr = new QuarantineManager(_testVaultDir);

        string tempSource = Path.Combine(_testVaultDir, "integrity_sample.bin");
        await File.WriteAllBytesAsync(tempSource, new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55 });

        var record = await quarantineMgr.IsolateFileAsync(tempSource, "Test.Integrity");

        // Falsifier un octet dans le coffre-fort (.locked)
        string lockedPath = Path.Combine(_testVaultDir, $"{record.Id}.locked");
        byte[] lockedBytes = await File.ReadAllBytesAsync(lockedPath);
        lockedBytes[0] ^= 0xFF; // corruption volontaire
        await File.WriteAllBytesAsync(lockedPath, lockedBytes);

        // La restauration doit échouer et NE PAS restaurer le fichier corrompu sur la cible
        bool integrityFailed = false;
        try
        {
            await quarantineMgr.RestoreFileAsync(record.Id);
        }
        catch (InvalidOperationException)
        {
            integrityFailed = true;
        }

        Assert.IsTrue(integrityFailed, "L'altération du binaire chiffré doit déclencher une violation d'intégrité.");
        Assert.IsFalse(File.Exists(tempSource), "Le fichier corrompu ne doit jamais être déployé sur la cible.");
    }

    // -------------------------------------------------------------
    // 3. TESTS DE SÉCURITÉ : JOURNALISATION & ASSAINISSEMENT (PII / SECRETS)
    // -------------------------------------------------------------

    [TestMethod]
    public void SecurityLogger_SanitizeLogContent_WhenApiKeyPresent_MasksSecret()
    {
        string rawLog = "Appel NVD API avec apiKey=nvd_secret_api_key_849204928 pour vérification CVE.";

        string sanitized = SecurityLogger.SanitizeLogContent(rawLog);

        Assert.IsFalse(sanitized.Contains("nvd_secret_api_key_849204928"), "La clé d'API ne doit pas figurer en clair dans les logs.");
        Assert.IsTrue(sanitized.Contains("***[REDACTED_SECRET]***"));
    }

    [TestMethod]
    public void SecurityLogger_SanitizeLogContent_WhenUserPathPresent_MasksUsername()
    {
        string rawLog = @"Analyse du fichier C:\Users\AliceDupont\Documents\Finance\report.docx terminée.";

        string sanitized = SecurityLogger.SanitizeLogContent(rawLog);

        Assert.IsFalse(sanitized.Contains("AliceDupont"), "Le nom de l'utilisateur Windows (PII) doit être masqué.");
        Assert.IsTrue(sanitized.Contains(@"C:\Users\[USER]\Documents\Finance\report.docx"));
    }

    [TestMethod]
    public async Task SecurityLogger_Log_DistinguishesLevelsAndWritesToFile()
    {
        string logDir = Path.Combine(_testVaultDir, "Logs");
        var logger = new SecurityLogger(logDir);

        logger.LogInformation("UnitTest", "Service démarré normalement.");
        logger.LogWarning("UnitTest", "Tentative d'accès non critique.");
        logger.LogError("UnitTest", "Erreur lors de la lecture du fichier.", new IOException("Disque plein"));
        logger.LogCritical("UnitTest", "Alerte de sécurité critique détectée !");

        var logs = await logger.GetRecentLogsAsync(10);

        Assert.IsTrue(logs.Count >= 4);
        Assert.IsTrue(logs.Any(l => l.Contains("[INFORMATION]")));
        Assert.IsTrue(logs.Any(l => l.Contains("[WARNING    ]")));
        Assert.IsTrue(logs.Any(l => l.Contains("[ERROR      ]")));
        Assert.IsTrue(logs.Any(l => l.Contains("[CRITICAL   ]")));
    }

    // -------------------------------------------------------------
    // 4. TESTS DE SÉCURITÉ : INTÉGRITÉ DES MODÈLES IA (ANTI-EMPOISONNEMENT)
    // -------------------------------------------------------------

    [TestMethod]
    public async Task OnnxMalwareInferenceService_VerifyModelIntegrityAsync_WhenHashMismatched_ReturnsFalse()
    {
        string dummyModelPath = Path.Combine(_testVaultDir, "fake_model.onnx");
        await File.WriteAllBytesAsync(dummyModelPath, new byte[2048]); // 2 KB

        string expectedTrustedHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // Empty file hash

        bool isValid = await OnnxMalwareInferenceService.VerifyModelIntegrityAsync(
            dummyModelPath, 
            CancellationToken.None, 
            expectedSha256: expectedTrustedHash);

        Assert.IsFalse(isValid, "Un modèle dont l'empreinte SHA-256 ne correspond pas à la clé de confiance doit être rejeté.");
    }

    [TestMethod]
    public async Task OnnxMalwareInferenceService_VerifyModelIntegrityAsync_WhenExactHash_ReturnsTrue()
    {
        string dummyModelPath = Path.Combine(_testVaultDir, "valid_model.onnx");
        byte[] payload = new byte[2048];
        for (int i = 0; i < payload.Length; i++) payload[i] = (byte)(i % 256);
        await File.WriteAllBytesAsync(dummyModelPath, payload);

        string computedHash;
        using (var sha = SHA256.Create())
        {
            computedHash = Convert.ToHexString(sha.ComputeHash(payload)).ToLowerInvariant();
        }

        bool isValid = await OnnxMalwareInferenceService.VerifyModelIntegrityAsync(
            dummyModelPath, 
            CancellationToken.None, 
            expectedSha256: computedHash);

        Assert.IsTrue(isValid, "Un modèle dont l'empreinte correspond exactement doit être validé.");
    }

    // -------------------------------------------------------------
    // 5. TESTS DE SÉCURITÉ : PRÉVENTION DES INJECTIONS SQL
    // -------------------------------------------------------------

    [TestMethod]
    public void SqliteInventoryRepository_EscapeSql_NeutralizesMaliciousTokens()
    {
        string maliciousInput = "TestApp'; DROP TABLE InstalledSoftware; --\r\nSELECT * FROM Users";

        string escaped = SqliteInventoryRepository.EscapeSql(maliciousInput);

        Assert.IsFalse(escaped.Contains("\r"));
        Assert.IsFalse(escaped.Contains("\n"));
        Assert.IsTrue(escaped.Contains("TestApp''; DROP TABLE InstalledSoftware; --"));
    }
}

