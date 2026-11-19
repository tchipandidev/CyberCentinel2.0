using System.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using CyberSentinel.Infrastructure.Vulnerabilities;

namespace CyberSentinel.UnitTests;

[TestClass]
public class NvdRateLimiterTests
{
    [TestMethod]
    public async Task WaitForPermitAsync_WithinLimit_CompletesImmediately()
    {
        // 5 requêtes autorisées avec min interval de 10ms pour test
        var limiter = new NvdRateLimiter(5, TimeSpan.FromSeconds(5), TimeSpan.FromMilliseconds(10));

        var sw = Stopwatch.StartNew();
        for (int i = 0; i < 3; i++)
        {
            await limiter.WaitForPermitAsync();
        }
        sw.Stop();

        Assert.IsTrue(sw.ElapsedMilliseconds < 500, "Les requêtes sous le quota doivent s'exécuter sans délai excessif.");
        Assert.AreEqual(3, limiter.GetActiveRequestCountInWindow());
    }

    [TestMethod]
    public async Task WaitForPermitAsync_ExceedingQuota_ThrottlesProperly()
    {
        // Limite à 2 requêtes par fenêtre de 300ms, min interval 10ms
        var limiter = new NvdRateLimiter(2, TimeSpan.FromMilliseconds(300), TimeSpan.FromMilliseconds(10));

        var sw = Stopwatch.StartNew();
        await limiter.WaitForPermitAsync(); // 1
        await limiter.WaitForPermitAsync(); // 2 (quota atteint)

        // La 3ème doit attendre la fin de la fenêtre glissante
        await limiter.WaitForPermitAsync(); // 3
        sw.Stop();

        Assert.IsTrue(sw.ElapsedMilliseconds >= 250, $"La 3ème requête aurait dû être ralentie. Écoulé: {sw.ElapsedMilliseconds}ms");
    }

    [TestMethod]
    public void Constructor_SetsDefaultNvdOfficialLimits()
    {
        var unauthenticated = new NvdRateLimiter(hasApiKey: false);
        Assert.AreEqual(5, unauthenticated.MaxRequestsPerWindow);
        Assert.AreEqual(TimeSpan.FromSeconds(30), unauthenticated.WindowDuration);
        Assert.AreEqual(TimeSpan.FromMilliseconds(6000), unauthenticated.MinIntervalBetweenRequests);

        var withKey = new NvdRateLimiter(hasApiKey: true);
        Assert.AreEqual(50, withKey.MaxRequestsPerWindow);
        Assert.AreEqual(TimeSpan.FromSeconds(30), withKey.WindowDuration);
        Assert.AreEqual(TimeSpan.FromMilliseconds(600), withKey.MinIntervalBetweenRequests);
    }
}

