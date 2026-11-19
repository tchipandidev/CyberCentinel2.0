using System.Diagnostics;
using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CyberSentinel.UnitTests;

public class Program
{
    public static async Task<int> Main(string[] args)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("================================================================");
        Console.WriteLine("       CYBERSENTINEL AI - SUITE DE TESTS UNITAIRES (GLOBAL)     ");
        Console.WriteLine("================================================================");
        Console.ResetColor();

        int passed = 0;
        int failed = 0;
        var stopwatch = Stopwatch.StartNew();

        var testClasses = new object[]
        {
            // Module 1 : Malware Detection & Quarantine
            new FileAnalyzerTests(),
            new ClamAvOutputParserTests(),
            new YaraScannerTests(),
            new QuarantineManagerTests(),
            new VerdictArbitratorTests(),

            // Module 2 : System Vulnerability & Update Management
            new VersionRangeMatcherTests(),
            new CpeResolverTests(),
            new WinGetParserTests(),
            new VulnerabilityAuditTests(),

            // Module 3 : AI PE Classification (EMBER / Machine Learning)
            new PeFeatureExtractorTests(),
            new EmberAiClassifierTests(),
            new OnnxMalwareInferenceServiceTests(),
            new EmberMultiEngineCorrelationTests(),

            // Module 4 : System Inventory Scanner & SQLite Persistence
            new InventoryReconciliationTests(),
            new WindowsRegistryDateParserTests(),
            new SqliteInventoryRepositoryTests(),

            // Module 5 : Vulnerability Detection & Management (NVD API / CVE / CVSS / OSV)
            new VulnerabilityMatchStatusTests(),
            new NvdRateLimiterTests(),
            new OsvVulnerabilityProviderTests(),
            new VulnerabilityScannerServiceTests(),

            // Module 6 : Update Management & WinGet Security
            new UpdateManagerServiceSecurityTests(),
            new WinGetCommandBuilderTests(),
            new JsonUpdateHistoryRepositoryTests(),

            // Module 7 : Dashboard, Statistics & PDF Reporting
            new DashboardServiceTests(),
            new PdfReportGeneratorTests(),
            new ReportServiceTests(),

            // Module 8 : Technical Security Audit & Hardening Validation
            new ApplicationSecurityAuditTests()
        };

        foreach (var testInstance in testClasses)
        {
            var type = testInstance.GetType();
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[CLASSE DE TEST] : {type.Name}");
            Console.ResetColor();

            var initMethod = type.GetMethods().FirstOrDefault(m => m.GetCustomAttribute<TestInitializeAttribute>() != null);
            var cleanupMethod = type.GetMethods().FirstOrDefault(m => m.GetCustomAttribute<TestCleanupAttribute>() != null);
            var testMethods = type.GetMethods().Where(m => m.GetCustomAttribute<TestMethodAttribute>() != null).ToList();

            foreach (var method in testMethods)
            {
                try
                {
                    initMethod?.Invoke(testInstance, null);

                    object? result = method.Invoke(testInstance, null);
                    if (result is Task task)
                    {
                        await task;
                    }

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write("  [✔ RÉUSSI] ");
                    Console.ResetColor();
                    Console.WriteLine(method.Name);
                    passed++;
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write("  [❌ ÉCHEC]  ");
                    Console.ResetColor();
                    Console.WriteLine($"{method.Name} -> {ex.InnerException?.Message ?? ex.Message}");
                    failed++;
                }
                finally
                {
                    try { cleanupMethod?.Invoke(testInstance, null); } catch { }
                }
            }
        }

        stopwatch.Stop();
        Console.WriteLine();
        Console.WriteLine("----------------------------------------------------------------");
        if (failed == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"BILAN : {passed} tests exécutés avec 100% de succès en {stopwatch.ElapsedMilliseconds} ms.");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"BILAN : {failed} test(s) échoué(s), {passed} réussi(s) en {stopwatch.ElapsedMilliseconds} ms.");
        }
        Console.ResetColor();
        Console.WriteLine("================================================================");

        return failed == 0 ? 0 : 1;
    }
}

