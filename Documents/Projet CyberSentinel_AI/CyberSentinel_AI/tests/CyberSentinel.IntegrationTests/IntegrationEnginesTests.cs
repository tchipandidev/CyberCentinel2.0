using System.Diagnostics;
using CyberSentinel.AI.Features;
using CyberSentinel.AI.Inference;
using CyberSentinel.AI.Models;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;
using CyberSentinel.Infrastructure.Persistence;
using CyberSentinel.Infrastructure.Security;
using CyberSentinel.Infrastructure.SystemIntegration;
using CyberSentinel.Infrastructure.Vulnerabilities;
using Xunit;

namespace CyberSentinel.IntegrationTests;

public class IntegrationEnginesTests
{
    private readonly string _testTempDir;

    public IntegrationEnginesTests()
    {
        _testTempDir = Path.Combine(Path.GetTempPath(), $"CyberSentinel_IT_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testTempDir);
    }

    public void Cleanup()
    {
        if (Directory.Exists(_testTempDir))
        {
            try { Directory.Delete(_testTempDir, true); } catch { }
        }
    }

    // -------------------------------------------------------------
    // 1. INTÉGRATION SQLITE & PERSISTANCE
    // -------------------------------------------------------------
    [Fact(DisplayName = "IT-01: SQLite - Persistance d'un instantané d'inventaire et dump DDL/DML")]
    public async Task Sqlite_InventoryRepository_PersistsAndLoadsHistorySuccessfully()
    {
        var repo = new SqliteInventoryRepository(_testTempDir);

        var session = new InventorySession
        {
            TotalApplicationsCount = 2,
            X64ApplicationsCount = 1,
            X86ApplicationsCount = 1,
            MachineName = "DESKTOP-TEST-QA",
            OsVersion = "Microsoft Windows 11 Enterprise 10.0.22631"
        };

        session.Applications.Add(new InstalledApplication
        {
            DisplayName = "VideoLAN VLC media player",
            Publisher = "VideoLAN",
            DisplayVersion = "3.0.17",
            PackageIdentifier = "VideoLAN.VLC",
            Architecture = AppArchitecture.X64,
            IdentificationSource = "Windows Registry (HKLM)"
        });

        session.Applications.Add(new InstalledApplication
        {
            DisplayName = "Git for Windows",
            Publisher = "The Git Development Community",
            DisplayVersion = "2.40.0",
            PackageIdentifier = "Git.Git",
            Architecture = AppArchitecture.X64,
            IdentificationSource = "WinGet"
        });

        await repo.SaveInventorySessionAsync(session);

        var history = await repo.GetInventoryHistoryAsync(10);
        Assert.NotEmpty(history);
        Assert.Equal(1, history.Count);

        var loadedSession = await repo.GetInventorySessionByIdAsync(session.Id);
        Assert.NotNull(loadedSession);
        Assert.Equal(2, loadedSession!.Applications.Count);

        // Vérification de la création du fichier SQLite dump
        string dumpPath = Path.Combine(_testTempDir, "inventory_records.sql");
        Assert.True(File.Exists(dumpPath));
        string dumpContent = await File.ReadAllTextAsync(dumpPath);
        Assert.Contains("VideoLAN VLC media player", dumpContent);
        Assert.Contains("Git for Windows", dumpContent);
    }

    // -------------------------------------------------------------
    // 2. INTÉGRATION CLAMAV ANTIVIRUS
    // -------------------------------------------------------------
    [Fact(DisplayName = "IT-02: ClamAV - Résolution de binaire et gestion des codes d'état")]
    public async Task ClamAv_Scanner_InterpretsOutputsAndRecoversGracefully()
    {
        var scanner = new ClamAvScanner();
        bool isInstalled = await scanner.IsAvailableAsync();

        // Analyse d'un fichier texte sain
        string cleanFile = Path.Combine(_testTempDir, "clean_test.txt");
        await File.WriteAllTextAsync(cleanFile, "Ceci est un fichier texte standard inoffensif pour test d'intégration.");

        var scanResult = await scanner.ScanFileAsync(cleanFile);
        Assert.NotNull(scanResult);

        if (!isInstalled)
        {
            Assert.Equal(ThreatVerdict.Unsupported, scanResult.Verdict);
        }
        else
        {
            Assert.Equal(ThreatVerdict.Clean, scanResult.Verdict);
        }

        // Test du parseur officiel ClamAV
        var parsedInfected = ClamAvScanner.ParseOutput("C:\\sample.exe: Win.Trojan.Generic-99 FOUND", "", 1, 120);
        Assert.Equal(ThreatVerdict.Malicious, parsedInfected.Verdict);
        Assert.Equal(RiskLevel.Critical, parsedInfected.RiskLevel);
        Assert.Equal("Win.Trojan.Generic-99", parsedInfected.ThreatName);
    }

    // -------------------------------------------------------------
    // 3. INTÉGRATION MOTEUR YARA HEURISTIQUE
    // -------------------------------------------------------------
    [Fact(DisplayName = "IT-03: YARA - Détection des règles intégrées Ransomware et Injection")]
    public async Task Yara_Scanner_DetectsSignaturesAccurately()
    {
        var yara = new YaraScanner();
        Assert.True(yara.LoadedRulesCount >= 5);

        // Fichier comportant une signature Ransomware Payment Note
        string ransomFile = Path.Combine(_testTempDir, "ransom_note_test.txt");
        await File.WriteAllTextAsync(ransomFile, "Attention! All your files have been encrypted! You must pay the ransom to recover your files.");

        var ransomResult = await yara.ScanFileAsync(ransomFile);
        Assert.Equal(ThreatVerdict.Malicious, ransomResult.Verdict);
        Assert.Equal(RiskLevel.High, ransomResult.RiskLevel);
        Assert.Contains("Ransomware", ransomResult.Details);

        // Fichier comportant une signature d'injection de mémoire dans les processus
        string injectFile = Path.Combine(_testTempDir, "process_inject_test.txt");
        await File.WriteAllTextAsync(injectFile, "KERNEL32 APIs: VirtualAllocEx followed by WriteProcessMemory and CreateRemoteThread execution.");

        var injectResult = await yara.ScanFileAsync(injectFile);
        Assert.Equal(ThreatVerdict.Malicious, injectResult.Verdict);
        Assert.Equal(RiskLevel.High, injectResult.RiskLevel);
        Assert.Contains("Process_Injection", injectResult.Details);
    }

    // -------------------------------------------------------------
    // 4. INTÉGRATION ONNX / EMBER IA MALWARE INFERENCE
    // -------------------------------------------------------------
    [Fact(DisplayName = "IT-04: ONNX/EMBER - Validation du vecteur de features et inférence IA")]
    public async Task Onnx_EmberInferenceService_EvaluatesFeaturesAccurately()
    {
        using var aiService = new OnnxMalwareInferenceService(useEmber2024: true);
        Assert.True(aiService.IsModelLoaded);
        Assert.Equal(EmberFeatureVector.Ember2024VectorDimension, aiService.ExpectedFeatureDimension);

        // Vecteur bénin standard
        var benignVector = new EmberFeatureVector(EmberFeatureVector.Ember2024VectorDimension);
        benignVector.Features[688 + 32] = 4.2f;

        var benignPred = await aiService.PredictAsync(benignVector);
        Assert.True(benignPred.IsSuccess);
        Assert.Equal(AiClassificationVerdict.Benign, benignPred.Verdict);
        Assert.True(benignPred.RawMalwareProbability < 0.30f);

        // Vecteur anomalie (entropie maximale de packer + caractéristiques malveillantes)
        var maliciousVector = new EmberFeatureVector(EmberFeatureVector.Ember2024VectorDimension);
        maliciousVector.Features[688 + 32] = 7.75f;
        maliciousVector.Features[688 + 33] = 1.0f;
        maliciousVector.Features[943 + 300] = 3.0f;
        maliciousVector.Features[943 + 301] = 2.0f;

        var maliciousPred = await aiService.PredictAsync(maliciousVector);
        Assert.True(maliciousPred.IsSuccess);
        Assert.Equal(AiClassificationVerdict.Malicious, maliciousPred.Verdict);
        Assert.True(maliciousPred.RawMalwareProbability >= 0.70f);
    }

    // -------------------------------------------------------------
    // 5. INTÉGRATION WINGET UPDATE MANAGER
    // -------------------------------------------------------------
    [Fact(DisplayName = "IT-05: WinGet - Parsing des flux tabulaires et mapping des codes de sortie")]
    public void WinGet_Manager_ParsesTablesAndTranslatesCodes()
    {
        string sampleWinGetOutput = 
            "Nom                           ID                     Version         Disponible     Source\r\n" +
            "------------------------------------------------------------------------------------------\r\n" +
            "Google Chrome                 Google.Chrome          120.0.6099.130  122.0.6261.95  winget\r\n" +
            "VLC media player              VideoLAN.VLC           3.0.18          3.0.20         winget\r\n" +
            "Git                           Git.Git                2.42.0          2.44.0         winget\r\n";

        var updates = WinGetManager.ParseWinGetOutput(sampleWinGetOutput);

        Assert.Equal(3, updates.Count / 2); // Chaque mise à jour est indexée par ID et par nom
        Assert.True(updates.ContainsKey("Google.Chrome"));
        Assert.Equal("120.0.6099.130", updates["Google.Chrome"].CurrentVersion);
        Assert.Equal("122.0.6261.95", updates["Google.Chrome"].AvailableVersion);

        // Validation mapping des codes de sortie
        string successDesc = WinGetManager.MapWinGetExitCode(0);
        Assert.Contains("succès", successDesc, StringComparison.OrdinalIgnoreCase);

        string privDesc = WinGetManager.MapWinGetExitCode(unchecked((int)0x8A15002B));
        Assert.Contains("Administrateur", privDesc, StringComparison.OrdinalIgnoreCase);
    }

    // -------------------------------------------------------------
    // 6. INTÉGRATION NVD API 2.0 & CATALOGUE DE VULNÉRABILITÉS
    // -------------------------------------------------------------
    [Fact(DisplayName = "IT-06: NVD API - Résolution CPE 2.3 et détection de plages de vulnérabilités")]
    public async Task Nvd_Provider_ResolvesCpeAndCorrelatesVulnerabilities()
    {
        var cache = new JsonVulnerabilityCache(Path.Combine(_testTempDir, "vuln_cache.json"));
        var rateLimiter = new NvdRateLimiter(hasApiKey: false);
        var provider = new NvdVulnerabilityProvider(cache, rateLimiter);

        // Application avec vulnérabilité critique connue (VLC 3.0.17 vulnérable à CVE-2022-41325)
        var vulnerableApp = new InstalledApplication
        {
            DisplayName = "VLC media player",
            Publisher = "VideoLAN",
            DisplayVersion = "3.0.17",
            PackageIdentifier = "VideoLAN.VLC"
        };

        var vulns = await provider.CheckVulnerabilitiesAsync(vulnerableApp);

        Assert.NotEmpty(vulns);
        var cveRecord = vulns.FirstOrDefault(v => v.CveId == "CVE-2022-41325");
        Assert.NotNull(cveRecord);
        Assert.Equal(CvssSeverity.High, cveRecord!.Severity);
        Assert.Equal(VulnerabilityMatchStatus.ConfirmedVulnerability, cveRecord.MatchStatus);
        Assert.Equal("3.0.18", cveRecord.PatchedVersion);
    }

    // -------------------------------------------------------------
    // 7. INTÉGRATION OSV (OPEN SOURCE VULNERABILITIES)
    // -------------------------------------------------------------
    [Fact(DisplayName = "IT-07: OSV - Vérification des vulnérabilités écosystèmes open source")]
    public async Task Osv_Provider_IdentifiesKnownPackages()
    {
        var cache = new JsonVulnerabilityCache(Path.Combine(_testTempDir, "osv_cache.json"));
        var osvProvider = new OsvVulnerabilityProvider(cache);

        var pythonApp = new InstalledApplication
        {
            DisplayName = "Python 3.8.5 (64-bit)",
            Publisher = "Python Software Foundation",
            DisplayVersion = "3.8.5",
            PackageIdentifier = "Python.Python.3.8"
        };

        var vulns = await osvProvider.CheckVulnerabilitiesAsync(pythonApp);
        Assert.NotEmpty(vulns);
        Assert.True(vulns.Any(v => v.CveId.Contains("GHSA") || v.CveId.Contains("CVE")));
    }
}

