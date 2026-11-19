using System.Diagnostics;
using CyberSentinel.AI.Inference;
using CyberSentinel.Application.DTOs;
using CyberSentinel.Application.Services;
using CyberSentinel.Infrastructure.Persistence;
using CyberSentinel.Infrastructure.Security;
using Xunit;

namespace CyberSentinel.IntegrationTests;

public class PerformanceBenchmarkTests
{
    private readonly string _testTempDir;

    public PerformanceBenchmarkTests()
    {
        _testTempDir = Path.Combine(Path.GetTempPath(), $"CyberSentinel_Perf_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testTempDir);
    }

    public void Cleanup()
    {
        if (Directory.Exists(_testTempDir))
        {
            try { Directory.Delete(_testTempDir, true); } catch { }
        }
    }

    [Fact(DisplayName = "PERF-01: Benchmark Débit & Temps d'analyse de fichiers")]
    public async Task Benchmark_FileScanThroughput_CompletesUnderStrictThresholds()
    {
        // Générer un lot de 50 fichiers de test
        string testFolder = Path.Combine(_testTempDir, "Batch50");
        Directory.CreateDirectory(testFolder);

        for (int i = 0; i < 50; i++)
        {
            string p = Path.Combine(testFolder, $"file_{i:D3}.txt");
            await File.WriteAllTextAsync(p, $"Contenu d'analyse de performance numéro {i} pour mesure du débit d'E/S.");
        }

        var orchestrator = new MalwareScanOrchestrator(
            new FileAnalyzer(),
            new ClamAvScanner(),
            new YaraScanner(),
            new JsonScanHistoryRepository(Path.Combine(_testTempDir, "perf_hist.json")),
            new OnnxMalwareInferenceService(useEmber2024: true));

        var sw = Stopwatch.StartNew();
        var session = await orchestrator.ScanDirectoryAsync(testFolder, recursive: false);
        sw.Stop();

        Assert.Equal(50, session.TotalFilesCount);
        // Doit traiter 50 fichiers en moins de 10 secondes (débit > 5 fichiers/sec)
        Assert.True(sw.ElapsedMilliseconds < 10_000, $"L'analyse de 50 fichiers a pris trop de temps : {sw.ElapsedMilliseconds} ms.");
    }

    [Fact(DisplayName = "PERF-02: Mesure de consommation mémoire (Allocation & Garbage Collection)")]
    public async Task Benchmark_MemoryUsage_StaysBoundedDuringHeavyScan()
    {
        // Créer un fichier volumineux de test (10 Mo)
        string bigFile = Path.Combine(_testTempDir, "big_payload.bin");
        byte[] buffer = new byte[10 * 1024 * 1024]; // 10 Mo
        new Random(42).NextBytes(buffer);
        await File.WriteAllBytesAsync(bigFile, buffer);

        GC.Collect(2, GCCollectionMode.Forced, true);
        GC.WaitForPendingFinalizers();
        long memBefore = GC.GetTotalMemory(true);

        var analyzer = new FileAnalyzer();
        var inspection = await analyzer.InspectFileAsync(bigFile);

        long memAfter = GC.GetTotalMemory(false);
        long memDeltaMb = (memAfter - memBefore) / (1024 * 1024);

        Assert.True(inspection.IsAccessible);
        Assert.Equal(10 * 1024 * 1024, inspection.FileSizeBytes);
        // L'allocation mémoire ne doit pas dépasser 3 fois la taille du fichier (streaming par tampons de 64 Ko)
        Assert.True(memDeltaMb < 35, $"L'augmentation de mémoire ({memDeltaMb} Mo) dépasse le seuil acceptable.");
    }

    [Fact(DisplayName = "PERF-03: Annulation instantanée et réactivité de l'interface utilisateur")]
    public async Task Benchmark_TaskCancellation_RespondsWithinStrictDelay()
    {
        // Créer un dossier avec 100 fichiers
        string cancelFolder = Path.Combine(_testTempDir, "CancelBatch");
        Directory.CreateDirectory(cancelFolder);

        for (int i = 0; i < 100; i++)
        {
            await File.WriteAllTextAsync(Path.Combine(cancelFolder, $"item_{i}.dat"), "Sample data for cancellation test");
        }

        var orchestrator = new MalwareScanOrchestrator(
            new FileAnalyzer(),
            new ClamAvScanner(),
            new YaraScanner(),
            new JsonScanHistoryRepository(Path.Combine(_testTempDir, "cancel_hist.json")));

        using var cts = new CancellationTokenSource();
        // Déclencher l'annulation immédiate pour tester la réactivité d'arrêt
        cts.Cancel();

        var sw = Stopwatch.StartNew();
        var session = await orchestrator.ScanDirectoryAsync(cancelFolder, recursive: false, cancellationToken: cts.Token);
        sw.Stop();

        Assert.Equal(CyberSentinel.Domain.Enums.ScanStatus.Cancelled, session.Status);
        // L'interruption doit être effective sous moins de 500 ms
        Assert.True(sw.ElapsedMilliseconds < 500, $"L'annulation a été trop lente : {sw.ElapsedMilliseconds} ms.");
    }
}

