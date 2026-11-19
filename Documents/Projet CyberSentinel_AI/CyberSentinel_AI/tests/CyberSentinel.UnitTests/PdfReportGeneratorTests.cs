using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using CyberSentinel.Application.DTOs;
using CyberSentinel.Domain.Enums;
using CyberSentinel.Infrastructure.Reporting;

namespace CyberSentinel.UnitTests;

[TestClass]
public class PdfReportGeneratorTests
{
    [TestMethod]
    public void GeneratePdf_ValidReport_ProducesStandardIsoPdfDocument()
    {
        var generator = new PdfReportGenerator();
        var report = new SecurityReportDto
        {
            Title = "CyberSentinel AI - Test Audit",
            ExecutiveSummary = "Synthèse d'audit automatisé pour les tests unitaires.",
            PostureScore = 87.5f,
            PostureVerdict = "Sécurisé",
            FilesScanned = 120,
            MaliciousFiles = 1,
            SuspiciousFiles = 2,
            CleanFiles = 117,
            CriticalVulnerabilities = 1,
            AvailableUpdates = 3,
            DetectedThreats = new List<ScannedFileDto>
            {
                new()
                {
                    FileName = "mimikatz.exe",
                    FilePath = @"C:\Temp\mimikatz.exe",
                    Sha256Hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    Verdict = ThreatVerdict.Malicious,
                    DetectionSummary = "ClamAV: Win.Trojan.Mimikatz-1"
                }
            },
            TopVulnerabilities = new List<VulnerabilityDto>
            {
                new()
                {
                    CveId = "CVE-2024-32002",
                    CvssScore = 9.8f,
                    Severity = CvssSeverity.Critical,
                    AffectedSoftware = "Git for Windows",
                    InstalledVersion = "2.44.0",
                    PatchedVersion = "2.45.1"
                }
            },
            StrategicRecommendations = new List<string>
            {
                "Isoler le fichier mimikatz.exe immédiatement.",
                "Mettre à jour Git vers la version 2.45.1."
            }
        };

        using var ms = new MemoryStream();
        generator.GeneratePdf(report, ms);

        byte[] pdfBytes = ms.ToArray();

        Assert.IsNotNull(pdfBytes);
        Assert.IsTrue(pdfBytes.Length > 200, "Le fichier PDF doit avoir une taille cohérente.");

        string pdfText = Encoding.Latin1.GetString(pdfBytes);

        // Validation de la conformité PDF 1.4
        Assert.IsTrue(pdfText.StartsWith("%PDF-1.4"), "Le fichier doit débuter par le marqueur officiel %PDF-1.4");
        Assert.IsTrue(pdfText.Contains("/Type /Catalog"), "Doit contenir le dictionnaire racine /Catalog");
        Assert.IsTrue(pdfText.Contains("/Type /Pages"), "Doit contenir la collection /Pages");
        Assert.IsTrue(pdfText.Contains("/Type /Page"), "Doit contenir la page /Page");
        Assert.IsTrue(pdfText.Contains("xref"), "Doit contenir la table de références croisées xref");
        Assert.IsTrue(pdfText.Contains("trailer"), "Doit contenir le dictionnaire trailer");
        Assert.IsTrue(pdfText.TrimEnd().EndsWith("%%EOF"), "Doit se terminer par le marqueur EOF");
    }
}
