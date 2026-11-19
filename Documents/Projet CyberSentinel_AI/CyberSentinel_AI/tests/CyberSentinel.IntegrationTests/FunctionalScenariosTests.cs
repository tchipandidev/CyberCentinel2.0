using CyberSentinel.AI.Inference;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.DTOs;
using CyberSentinel.Application.Services;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;
using CyberSentinel.Infrastructure.Logging;
using CyberSentinel.Infrastructure.Persistence;
using CyberSentinel.Infrastructure.Reporting;
using CyberSentinel.Infrastructure.Security;
using CyberSentinel.Infrastructure.SystemIntegration;
using CyberSentinel.Infrastructure.Vulnerabilities;
using Xunit;

namespace CyberSentinel.IntegrationTests;

public class FunctionalScenariosTests
{
    private readonly string _testTempDir;

    public FunctionalScenariosTests()
    {
        _testTempDir = Path.Combine(Path.GetTempPath(), $"CyberSentinel_Func_{Guid.NewGuid():N}");
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
    // SCÉNARIO A : Analyse d'un fichier sain
    // -------------------------------------------------------------
    [Fact(DisplayName = "SCENARIO-A: Analyse d'un fichier sain")]
    public async Task ScenarioA_ScanCleanFile_ReturnsCleanVerdict()
    {
        string cleanFilePath = Path.Combine(_testTempDir, "document_sain.txt");
        await File.WriteAllTextAsync(cleanFilePath, "Documentation de référence CyberSentinel AI. Fichier texte bénin et propre.");

        var orchestrator = CreateStandardOrchestrator();

        var record = await orchestrator.ScanSingleFileAsync(cleanFilePath);

        Assert.NotNull(record);
        Assert.Equal(ThreatVerdict.Clean, record.Verdict);
        Assert.Equal(RiskLevel.None, record.RiskLevel);
        Assert.False(record.IsInfected);
        Assert.NotEmpty(record.Sha256Hash);
    }

    // -------------------------------------------------------------
    // SCÉNARIO B : Détection d'un fichier malveillant de test
    // -------------------------------------------------------------
    [Fact(DisplayName = "SCENARIO-B: Détection d'un fichier malveillant de test")]
    public async Task ScenarioB_ScanMaliciousTestFile_DetectsThreatAndFlagsMalicious()
    {
        string maliciousFilePath = Path.Combine(_testTempDir, "ransomware_test_sample.txt");
        // Signature heuristique de test Ransomware reconnue par le moteur YARA
        await File.WriteAllTextAsync(maliciousFilePath, "Attention! All your files have been encrypted! You must pay the ransom to recover your files.");

        var orchestrator = CreateStandardOrchestrator();

        var record = await orchestrator.ScanSingleFileAsync(maliciousFilePath);

        Assert.NotNull(record);
        Assert.Equal(ThreatVerdict.Malicious, record.Verdict);
        Assert.Equal(RiskLevel.Critical, record.RiskLevel);
        Assert.True(record.IsInfected);
        Assert.NotEmpty(record.Threats);
    }

    // -------------------------------------------------------------
    // SCÉNARIO C : Analyse d'un dossier
    // -------------------------------------------------------------
    [Fact(DisplayName = "SCENARIO-C: Analyse d'un dossier complet avec récursivité")]
    public async Task ScenarioC_ScanDirectory_ProcessesAllFilesAndCalculatesAggregates()
    {
        string baseDir = Path.Combine(_testTempDir, "FolderScanC");
        string subDir1 = Path.Combine(baseDir, "SubFolder1");
        string subDir2 = Path.Combine(baseDir, "SubFolder2");
        Directory.CreateDirectory(subDir1);
        Directory.CreateDirectory(subDir2);

        await File.WriteAllTextAsync(Path.Combine(subDir1, "file1.txt"), "Fichier sain 1");
        await File.WriteAllTextAsync(Path.Combine(subDir1, "file2.txt"), "Fichier sain 2");
        await File.WriteAllTextAsync(Path.Combine(subDir2, "threat.txt"), "Attention! All your files have been encrypted! You must pay the ransom to recover your files.");

        var orchestrator = CreateStandardOrchestrator();
        var progressReports = new List<ScanProgressDto>();
        var progress = new Progress<ScanProgressDto>(p => progressReports.Add(p));

        var session = await orchestrator.ScanDirectoryAsync(baseDir, recursive: true, progress: progress);

        Assert.NotNull(session);
        Assert.Equal(ScanStatus.Completed, session.Status);
        Assert.True(session.TotalFilesCount >= 3);
        Assert.Equal(1, session.MaliciousFilesCount);
        Assert.True(session.CleanFilesCount >= 2);
    }

    // -------------------------------------------------------------
    // SCÉNARIO D : Analyse d'un fichier non pris en charge par l'IA
    // -------------------------------------------------------------
    [Fact(DisplayName = "SCENARIO-D: Analyse d'un fichier non-PE non pris en charge par l'IA")]
    public async Task ScenarioD_ScanNonPeFile_AiBypassesGracefullyWithoutError()
    {
        string csvFile = Path.Combine(_testTempDir, "data.csv");
        await File.WriteAllTextAsync(csvFile, "id,name,value\n1,alice,100\n2,bob,200");

        var aiService = new OnnxMalwareInferenceService(useEmber2024: true);
        var result = await aiService.ClassifyPeFileAsync(csvFile);

        Assert.NotNull(result);
        Assert.Equal(ThreatVerdict.Clean, result.Verdict);
        Assert.Contains("non-PE", result.Details, StringComparison.OrdinalIgnoreCase);
    }

    // -------------------------------------------------------------
    // SCÉNARIO E : Détection d'un logiciel obsolète
    // -------------------------------------------------------------
    [Fact(DisplayName = "SCENARIO-E: Détection d'un logiciel obsolète")]
    public async Task ScenarioE_DetectOutdatedSoftware_IdentifiesAvailableUpgrade()
    {
        var inventoryService = new MockInventoryService(new List<InstalledApplication>
        {
            new() { DisplayName = "Google Chrome", DisplayVersion = "120.0.0.0", PackageIdentifier = "Google.Chrome" }
        });

        var updateManager = new MockUpdateManager(new Dictionary<string, SoftwareUpdateInfo>
        {
            ["Google.Chrome"] = new()
            {
                ApplicationName = "Google Chrome",
                PackageIdentifier = "Google.Chrome",
                CurrentVersion = "120.0.0.0",
                AvailableVersion = "122.0.0.0",
                Status = UpdateStatus.UpdateAvailable
            }
        });

        var vulnProvider = new MockVulnerabilityProvider();
        var updateService = new UpdateManagerService(inventoryService, vulnProvider, updateManager, new JsonUpdateHistoryRepository(Path.Combine(_testTempDir, "upd.json")));

        var updates = await updateService.CheckUpdatesAsync();

        Assert.NotEmpty(updates);
        var chromeUpdate = updates.FirstOrDefault(u => u.PackageIdentifier == "Google.Chrome");
        Assert.NotNull(chromeUpdate);
        Assert.True(chromeUpdate!.IsAvailable);
        Assert.Equal("122.0.0.0", chromeUpdate.AvailableVersion);
    }

    // -------------------------------------------------------------
    // SCÉNARIO F : Recherche de vulnérabilités
    // -------------------------------------------------------------
    [Fact(DisplayName = "SCENARIO-F: Recherche de vulnérabilités CVE pour un logiciel inventorié")]
    public async Task ScenarioF_SearchVulnerabilities_ReturnsCuratedCves()
    {
        var cache = new JsonVulnerabilityCache(Path.Combine(_testTempDir, "vcache.json"));
        var provider = new NvdVulnerabilityProvider(cache);

        var app = new InstalledApplication
        {
            DisplayName = "Git for Windows",
            Publisher = "The Git Development Community",
            DisplayVersion = "2.39.0",
            PackageIdentifier = "Git.Git"
        };

        var vulns = await provider.CheckVulnerabilitiesAsync(app);

        Assert.NotEmpty(vulns);
        var rceVuln = vulns.FirstOrDefault(v => v.CveId == "CVE-2024-32002");
        Assert.NotNull(rceVuln);
        Assert.Equal(CvssSeverity.Critical, rceVuln!.Severity);
    }

    // -------------------------------------------------------------
    // SCÉNARIO G : Recherche de mises à jour
    // -------------------------------------------------------------
    [Fact(DisplayName = "SCENARIO-G: Recherche de mises à jour et corrélation de sécurité")]
    public async Task ScenarioG_SearchUpdates_CorrelatesCvesAndPatches()
    {
        var inventoryService = new MockInventoryService(new List<InstalledApplication>
        {
            new() { DisplayName = "VLC media player", DisplayVersion = "3.0.17", PackageIdentifier = "VideoLAN.VLC" }
        });

        var updateManager = new MockUpdateManager(new Dictionary<string, SoftwareUpdateInfo>
        {
            ["VideoLAN.VLC"] = new()
            {
                ApplicationName = "VLC media player",
                PackageIdentifier = "VideoLAN.VLC",
                CurrentVersion = "3.0.17",
                AvailableVersion = "3.0.18",
                Status = UpdateStatus.UpdateAvailable
            }
        });

        var cache = new JsonVulnerabilityCache(Path.Combine(_testTempDir, "vcache.json"));
        var vulnProvider = new NvdVulnerabilityProvider(cache);
        var updateService = new UpdateManagerService(inventoryService, vulnProvider, updateManager, new JsonUpdateHistoryRepository(Path.Combine(_testTempDir, "upd.json")));

        var updates = await updateService.CheckUpdatesAsync();

        var vlc = updates.First(u => u.PackageIdentifier == "VideoLAN.VLC");
        Assert.True(vlc.IsAvailable);
        Assert.True(vlc.HasCriticalSecurityPatch);
        Assert.Contains("CVE-2022-41325", vlc.CVEsAddressed);
    }

    // -------------------------------------------------------------
    // SCÉNARIO H : Mise en quarantaine et restauration
    // -------------------------------------------------------------
    [Fact(DisplayName = "SCENARIO-H: Mise en quarantaine chiffrée et restauration atomique")]
    public async Task ScenarioH_QuarantineIsolationAndRestore_MaintainsIntegrity()
    {
        string vaultDir = Path.Combine(_testTempDir, "Vault");
        var qm = new QuarantineManager(vaultDir);

        string infectedFile = Path.Combine(_testTempDir, "ransom_sample.bin");
        await File.WriteAllBytesAsync(infectedFile, new byte[] { 0x4D, 0x5A, 0x01, 0x02, 0x03, 0x04 });

        // 1. Mise en quarantaine
        var record = await qm.IsolateFileAsync(infectedFile, "Ransomware.Test.Detected");
        Assert.False(File.Exists(infectedFile), "Le fichier original doit être supprimé de son emplacement d'origine.");
        Assert.True(File.Exists(record.QuarantinedFilePath), "Le fichier verrouillé doit exister dans le coffre-fort.");

        // 2. Restauration
        bool restored = await qm.RestoreFileAsync(record.Id);
        Assert.True(restored);
        Assert.True(File.Exists(infectedFile), "Le fichier doit être restauré avec succès à son emplacement d'origine.");
        Assert.False(File.Exists(record.QuarantinedFilePath), "Le fichier du coffre doit être nettoyé après restauration.");
    }

    // -------------------------------------------------------------
    // SCÉNARIO I : Génération de rapport et export PDF
    // -------------------------------------------------------------
    [Fact(DisplayName = "SCENARIO-I: Génération d'un rapport de sécurité et export PDF")]
    public async Task ScenarioI_GenerateReport_CreatesValidIsoPdfDocument()
    {
        var historyRepo = new JsonScanHistoryRepository(Path.Combine(_testTempDir, "scan_history.json"));
        var inventoryRepo = new SqliteInventoryRepository(_testTempDir);
        var pdfGen = new PdfReportGenerator();

        var session = new ScanSession
        {
            Type = ScanType.SingleFile,
            TargetPath = @"C:\Users\Target\sample.exe",
            Status = ScanStatus.Completed,
            StartedAt = DateTime.UtcNow.AddMinutes(-5),
            CompletedAt = DateTime.UtcNow,
            DurationMs = 1200
        };
        session.RecordFile(new ScannedFileRecord
        {
            FilePath = @"C:\Users\Target\sample.exe",
            FileName = "sample.exe",
            Verdict = ThreatVerdict.Malicious,
            RiskLevel = RiskLevel.High,
            Sha256Hash = "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0"
        });
        await historyRepo.SaveSessionAsync(session);

        var reportService = new ReportService(
            historyRepo, 
            inventoryRepo, 
            new MockVulnerabilityScannerService(), 
            new MockUpdateManagerService(), 
            pdfGen);

        var reportDto = await reportService.GenerateFullReportAsync();
        Assert.NotNull(reportDto);
        Assert.True(reportDto.MaliciousFiles >= 1);
        Assert.NotEmpty(reportDto.StrategicRecommendations);

        string pdfPath = Path.Combine(_testTempDir, "SecurityAudit_FinalReport.pdf");
        await reportService.ExportReportToPdfAsync(reportDto, pdfPath);

        Assert.True(File.Exists(pdfPath));
        var pdfBytes = await File.ReadAllBytesAsync(pdfPath);
        Assert.True(pdfBytes.Length > 500);
        string header = System.Text.Encoding.ASCII.GetString(pdfBytes, 0, 8);
        Assert.Contains("%PDF-1.4", header);
    }

    // -------------------------------------------------------------
    // HELPERS & MOCKS
    // -------------------------------------------------------------
    private MalwareScanOrchestrator CreateStandardOrchestrator()
    {
        var fileAnalyzer = new FileAnalyzer();
        var clamScanner = new ClamAvScanner();
        var yaraScanner = new YaraScanner();
        var aiClassifier = new OnnxMalwareInferenceService(useEmber2024: true);
        var historyRepo = new JsonScanHistoryRepository(Path.Combine(_testTempDir, "scans.json"));

        return new MalwareScanOrchestrator(fileAnalyzer, clamScanner, yaraScanner, historyRepo, aiClassifier);
    }

    private class MockInventoryService : ISystemInventoryService
    {
        private readonly IReadOnlyList<InstalledApplication> _apps;
        public MockInventoryService(IReadOnlyList<InstalledApplication> apps) => _apps = apps;
        public Task<IReadOnlyList<InstalledApplication>> GetInstalledApplicationsAsync(CancellationToken ct = default) => Task.FromResult(_apps);
        public Task<IReadOnlyList<InstalledApplication>> GetInstalledApplicationsAsync(IProgress<(string Step, int Percent)>? p, CancellationToken ct = default) => Task.FromResult(_apps);
    }

    private class MockUpdateManager : IUpdateManager
    {
        private readonly IReadOnlyDictionary<string, SoftwareUpdateInfo> _map;
        public MockUpdateManager(IReadOnlyDictionary<string, SoftwareUpdateInfo> map) => _map = map;
        public bool IsWinGetAvailable => true;
        public string GetWinGetVersion() => "v1.7.10691";
        public Task<IReadOnlyDictionary<string, SoftwareUpdateInfo>> DiscoverAvailableUpdatesAsync(IEnumerable<InstalledApplication> apps, CancellationToken ct = default) => Task.FromResult(_map);
        public Task<IReadOnlyDictionary<string, SoftwareUpdateInfo>> DiscoverAllUpgradesAsync(CancellationToken ct = default) => Task.FromResult(_map);
        public Task<UpdateExecutionResult> ApplyUpdateAsync(string packageId, IProgress<string>? consoleOutput = null, CancellationToken ct = default) => Task.FromResult(new UpdateExecutionResult(true, "Success", null, 0));
        public Task<UpdateExecutionResult> ApplyAllUpdatesAsync(IProgress<string>? consoleOutput = null, CancellationToken ct = default) => Task.FromResult(new UpdateExecutionResult(true, "All Success", null, 0));
    }

    private class MockVulnerabilityProvider : IVulnerabilityProvider
    {
        public string ProviderName => "Mock Provider";
        public Task<IReadOnlyList<VulnerabilityRecord>> CheckVulnerabilitiesAsync(InstalledApplication app, CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<VulnerabilityRecord>>(new List<VulnerabilityRecord>());
    }

    private class MockVulnerabilityScannerService : IVulnerabilityScannerService
    {
        public Task<IReadOnlyList<VulnerabilityDto>> ScanVulnerabilitiesAsync(IProgress<(string Status, int Percent)>? progress = null, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<VulnerabilityDto>>(new List<VulnerabilityDto>());
        public Task<IReadOnlyList<VulnerabilityDto>> ScanApplicationsAsync(IEnumerable<InstalledApplication> applications, IProgress<(string Status, int Percent)>? progress = null, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<VulnerabilityDto>>(new List<VulnerabilityDto>());
    }

    private class MockUpdateManagerService : IUpdateManagerService
    {
        public bool IsAdministrator => true;
        public bool IsWinGetAvailable => true;
        public string WinGetVersion => "v1.7.1";
        public Task<IReadOnlyList<SoftwareUpdateDto>> CheckUpdatesAsync(IProgress<(string Status, int Percent)>? progress = null, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<SoftwareUpdateDto>>(new List<SoftwareUpdateDto>());
        public Task<UpdateOperationResultDto> UpgradePackageAsync(string packageId, bool isConfirmed, IProgress<string>? consoleOutput = null, CancellationToken cancellationToken = default) =>
            Task.FromResult(new UpdateOperationResultDto { Success = true, PackageId = packageId, Message = "Upgraded", ExitCode = 0 });
        public Task<UpdateOperationResultDto> UpgradeAllAsync(bool isConfirmed, IProgress<string>? consoleOutput = null, CancellationToken cancellationToken = default) =>
            Task.FromResult(new UpdateOperationResultDto { Success = true, PackageId = "ALL", Message = "Upgraded All", ExitCode = 0 });
        public Task<IReadOnlyList<UpdateHistoryRecord>> GetHistoryAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<UpdateHistoryRecord>>(new List<UpdateHistoryRecord>());
    }
}

