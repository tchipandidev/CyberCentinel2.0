using System.Diagnostics;
using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CyberSentinel.SecurityTests;

public class Program
{
    public static async Task<int> Main(string[] args)
    {
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("================================================================");
        Console.WriteLine("     CYBERSENTINEL AI - SUITE DE TESTS DE SÉCURITÉ APPLICATIF   ");
        Console.WriteLine("================================================================");
        Console.ResetColor();

        int passed = 0;
        int failed = 0;
        var stopwatch = Stopwatch.StartNew();

        var testClasses = new object[]
        {
            new SecurityAuditValidationTests()
        };

        foreach (var testInstance in testClasses)
        {
            var type = testInstance.GetType();
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[CLASSE DE TEST SÉCURITÉ] : {type.Name}");
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
                    Console.Write("  [✔ SÉCURISÉ] ");
                    Console.ResetColor();
                    Console.WriteLine(method.Name);
                    passed++;
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write("  [❌ VULNÉRABLE] ");
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
            Console.WriteLine($"BILAN SÉCURITÉ : {passed} tests de sécurité validés avec 100% de succès en {stopwatch.ElapsedMilliseconds} ms.");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"BILAN SÉCURITÉ : {failed} échecs / {passed + failed} tests en {stopwatch.ElapsedMilliseconds} ms.");
        }
        Console.ResetColor();
        Console.WriteLine("================================================================");

        return failed == 0 ? 0 : 1;
    }
}

