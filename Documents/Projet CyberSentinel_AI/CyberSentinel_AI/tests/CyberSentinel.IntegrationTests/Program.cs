using System.Diagnostics;
using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CyberSentinel.IntegrationTests;

public class Program
{
    public static async Task<int> Main(string[] args)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("==================================================================");
        Console.WriteLine("  CYBERSENTINEL AI - SUITE DE TESTS D'INTÉGRATION, SCÉNARIOS & PERF");
        Console.WriteLine("==================================================================");
        Console.ResetColor();

        int passed = 0;
        int failed = 0;
        var stopwatch = Stopwatch.StartNew();

        var testClasses = new object[]
        {
            new IntegrationEnginesTests(),
            new FunctionalScenariosTests(),
            new PerformanceBenchmarkTests()
        };

        foreach (var testInstance in testClasses)
        {
            var type = testInstance.GetType();
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[CLASSE DE TEST] : {type.Name}");
            Console.ResetColor();

            var cleanupMethod = type.GetMethod("Cleanup", BindingFlags.Public | BindingFlags.Instance);
            var testMethods = type.GetMethods()
                .Where(m => m.GetCustomAttribute<TestMethodAttribute>() != null)
                .ToList();

            foreach (var method in testMethods)
            {
                var factAttr = method.GetCustomAttribute<Xunit.FactAttribute>();
                string displayName = factAttr?.DisplayName ?? method.Name;

                try
                {
                    object? result = method.Invoke(testInstance, null);
                    if (result is Task task)
                    {
                        await task;
                    }

                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write("  [✔ SUCCÈS] ");
                    Console.ResetColor();
                    Console.WriteLine(displayName);
                    passed++;
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write("  [❌ ÉCHEC]  ");
                    Console.ResetColor();
                    Console.WriteLine($"{displayName} -> {ex.InnerException?.Message ?? ex.Message}");
                    failed++;
                }
            }

            try { cleanupMethod?.Invoke(testInstance, null); } catch { }
        }

        stopwatch.Stop();
        Console.WriteLine();
        Console.WriteLine("------------------------------------------------------------------");
        if (failed == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"BILAN GLOBAL : {passed} tests exécutés avec 100% de succès en {stopwatch.ElapsedMilliseconds} ms.");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"BILAN GLOBAL : {failed} échecs / {passed + failed} tests en {stopwatch.ElapsedMilliseconds} ms.");
        }
        Console.ResetColor();
        Console.WriteLine("==================================================================");

        return failed == 0 ? 0 : 1;
    }
}

