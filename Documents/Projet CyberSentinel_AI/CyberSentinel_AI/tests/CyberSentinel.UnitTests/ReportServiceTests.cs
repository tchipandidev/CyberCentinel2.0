using Microsoft.VisualStudio.TestTools.UnitTesting;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.DTOs;
using CyberSentinel.Application.Services;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;
using CyberSentinel.Infrastructure.Reporting;

namespace CyberSentinel.UnitTests;

[TestClass]
public class ReportServiceTests
{
    private class MockScanHistoryRepo : IScanHistoryRepository
    {
        public List<ScanSession> Sessions { get; } = new();

        public Task SaveSessionAsync(ScanSession session, CancellationToken cancellationToken = default)
        {
            Sessions.Add(session);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<ScanSession>> GetRecentSessionsAsync(int maxCount = 20, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<ScanSession>>(Sessions);
        }

        public Task<ScanSession?> GetSessionByIdAsync(Guid sessionId, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Sessions.FirstOrDefault(s => s.Id == sessionId));
        }
    }

    private class MockInventoryRepo : IInventoryRepository
    {
        public Task SaveInventorySessionAsync(InventorySession session, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task<IReadOnlyList<InventorySession>> GetInventoryHistoryAsync(int maxCount = 10, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<InventorySession>>(new List<InventorySession>());
        public Task<InventorySession?> GetInventorySessionByIdAsync(Guid sessionId, CancellationToken cancellationToken = default) => Task.FromResult<InventorySession?>(null);
    }

    private class MockVulnService : IVulnerabilityScannerService
    {
        public Task<IReadOnlyList<VulnerabilityDto>> ScanVulnerabilitiesAsync(IProgress<(string Status, int Percent)>? progress = null, CancellationToken cancellationToken = default)
        {
            var list = new List<VulnerabilityDto>
            {
                new()
                {
                    CveId = "CVE-2023-4863",
                    Severity = CvssSeverity.Critical,
                    CvssScore = 8.8f,
                    AffectedSoftware = "Google Chrome"
                }
            };
            return Task.FromResult<IReadOnlyList<VulnerabilityDto>>(list);
        }

        public Task<IReadOnlyList<VulnerabilityDto>> ScanApplicationsAsync(IEnumerable<InstalledApplication> applications, IProgress<(string Status, int Percent)>? progress = null, CancellationToken cancellationToken = default)
        {
            return ScanVulnerabilitiesAsync(progress, cancellationToken);
        }
    }

    private class MockUpdateService : IUpdateManagerService
    {
        public bool IsAdministrator => true;
        public bool IsWinGetAvailable => true;
        public string WinGetVersion => "v1.8";

        public Task<IReadOnlyList<SoftwareUpdateDto>> CheckUpdatesAsync(IProgress<(string Status, int Percent)>? progress = null, CancellationToken cancellationToken = default)
        {
            var list = new List<SoftwareUpdateDto>
            {
                new()
                {
                    ApplicationName = "Google Chrome",
                    PackageIdentifier = "Google.Chrome",
                    IsAvailable = true,
                    HasCriticalSecurityPatch = true
                }
            };
            return Task.FromResult<IReadOnlyList<SoftwareUpdateDto>>(list);
        }

        public Task<UpdateOperationResultDto> UpgradePackageAsync(string packageId, bool isConfirmed, IProgress<string>? consoleOutput = null, CancellationToken cancellationToken = default) => Task.FromResult(new UpdateOperationResultDto { Success = true });
        public Task<UpdateOperationResultDto> UpgradeAllAsync(bool isConfirmed, IProgress<string>? consoleOutput = null, CancellationToken cancellationToken = default) => Task.FromResult(new UpdateOperationResultDto { Success = true });
        public Task<IReadOnlyList<UpdateHistoryRecord>> GetHistoryAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<UpdateHistoryRecord>>(new List<UpdateHistoryRecord>());
    }

    [TestMethod]
    public async Task GenerateFullReportAsync_ConsolidatesMetricsAndActionPlan()
    {
        var scanRepo = new MockScanHistoryRepo();
        var session = new ScanSession
        {
            TargetPath = @"C:\Test",
            ScannedFilesCount = 20,
            CleanFilesCount = 19,
            MaliciousFilesCount = 1
        };
        session.Files.Add(new ScannedFileRecord
        {
            FilePath = @"C:\Test\malware.exe",
            Sha256Hash = "1234567890abcdef",
            Verdict = ThreatVerdict.Malicious
        });
        scanRepo.Sessions.Add(session);

        var reportService = new ReportService(
            scanRepo,
            new MockInventoryRepo(),
            new MockVulnService(),
            new MockUpdateService(),
            new PdfReportGenerator());

        var report = await reportService.GenerateFullReportAsync();

        Assert.IsNotNull(report);
        Assert.AreEqual(20, report.FilesScanned);
        Assert.AreEqual(1, report.MaliciousFiles);
        Assert.AreEqual(1, report.CriticalVulnerabilities);
        Assert.AreEqual(1, report.AvailableUpdates);
        Assert.IsTrue(report.StrategicRecommendations.Count >= 2);
    }

    [TestMethod]
    public async Task ExportReportToPdfAsync_CreatesValidFileOnDisk()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "CyberSentinel_PdfExportTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string pdfPath = Path.Combine(tempDir, "report_test.pdf");

        try
        {
            var reportService = new ReportService(
                new MockScanHistoryRepo(),
                new MockInventoryRepo(),
                new MockVulnService(),
                new MockUpdateService(),
                new PdfReportGenerator());

            var report = new SecurityReportDto
            {
                Title = "Test Report Export",
                ExecutiveSummary = "Test export execution"
            };

            string exported = await reportService.ExportReportToPdfAsync(report, pdfPath);

            Assert.IsTrue(File.Exists(exported), "Le fichier PDF doit exister sur le disque.");
            var fi = new FileInfo(exported);
            Assert.IsTrue(fi.Length > 100, "Le fichier PDF ne doit pas être vide.");
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }
}
