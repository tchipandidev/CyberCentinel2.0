using Microsoft.VisualStudio.TestTools.UnitTesting;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;
using CyberSentinel.Domain.Rules;

namespace CyberSentinel.UnitTests;

[TestClass]
public class EmberMultiEngineCorrelationTests
{
    [TestMethod]
    public void Fusion_ClamAvMaliciousAndEmberClean_AntivirusTakesPrecedence()
    {
        // RÈGLE FONDAMENTALE : L'IA ne doit JAMAIS annuler une détection formelle de l'antivirus
        var results = new List<EngineScanResult>
        {
            EngineScanResult.Success(EngineType.ClamAV, ThreatVerdict.Malicious, RiskLevel.Critical, "Win.Trojan.Agent-1234", "Signature certifiée", 80),
            EngineScanResult.Success(EngineType.YARA, ThreatVerdict.Clean, RiskLevel.None, null, "Aucune règle YARA", 30),
            EngineScanResult.Success(EngineType.EMBER_AI, ThreatVerdict.Clean, RiskLevel.None, null, "Score IA: 0.12 (Bénin)", 15)
        };

        var (verdict, risk) = VerdictArbitrator.Evaluate(results);

        Assert.AreEqual(ThreatVerdict.Malicious, verdict, "L'antivirus ClamAV doit l'emporter sur le score bénin de l'IA.");
        Assert.AreEqual(RiskLevel.Critical, risk);
    }

    [TestMethod]
    public void Fusion_YaraCriticalAndEmberClean_YaraTakesPrecedence()
    {
        var results = new List<EngineScanResult>
        {
            EngineScanResult.Success(EngineType.ClamAV, ThreatVerdict.Clean, RiskLevel.None, null, "OK", 80),
            EngineScanResult.Success(EngineType.YARA, ThreatVerdict.Malicious, RiskLevel.Critical, "Ransomware_LockBit_Note", "Note de rançon", 20),
            EngineScanResult.Success(EngineType.EMBER_AI, ThreatVerdict.Clean, RiskLevel.None, null, "Score IA: 0.20 (Bénin)", 15)
        };

        var (verdict, risk) = VerdictArbitrator.Evaluate(results);

        Assert.AreEqual(ThreatVerdict.Malicious, verdict);
        Assert.AreEqual(RiskLevel.Critical, risk);
    }

    [TestMethod]
    public void Fusion_YaraSuspiciousAndEmberMalicious_ElevatesToMaliciousHigh()
    {
        // Corrélation croisée : avertissement YARA + IA alarmante -> élévation
        var results = new List<EngineScanResult>
        {
            EngineScanResult.Success(EngineType.ClamAV, ThreatVerdict.Clean, RiskLevel.None, null, "OK", 80),
            EngineScanResult.Success(EngineType.YARA, ThreatVerdict.Suspicious, RiskLevel.Medium, "Process_Injection_Heuristic", "APIs injection", 25),
            EngineScanResult.Success(EngineType.EMBER_AI, ThreatVerdict.Malicious, RiskLevel.High, "EMBER2024.MalwareDetected", "Probabilité 0.88", 15)
        };

        var (verdict, risk) = VerdictArbitrator.Evaluate(results);

        Assert.AreEqual(ThreatVerdict.Malicious, verdict);
        Assert.AreEqual(RiskLevel.High, risk);
    }

    [TestMethod]
    public void Fusion_OnlyEmberMalicious_YieldsHeuristicMaliciousAlert()
    {
        // Cas d'un malware 0-day inconnu des signatures traditionnelles
        var results = new List<EngineScanResult>
        {
            EngineScanResult.Success(EngineType.ClamAV, ThreatVerdict.Clean, RiskLevel.None, null, "OK", 80),
            EngineScanResult.Success(EngineType.YARA, ThreatVerdict.Clean, RiskLevel.None, null, "Clean", 20),
            EngineScanResult.Success(EngineType.EMBER_AI, ThreatVerdict.Malicious, RiskLevel.High, "EMBER2024.MalwareDetected", "Probabilité 0.94", 18)
        };

        var (verdict, risk) = VerdictArbitrator.Evaluate(results);

        Assert.AreEqual(ThreatVerdict.Malicious, verdict);
        Assert.AreEqual(RiskLevel.High, risk);
    }

    [TestMethod]
    public void Fusion_AllEnginesClean_YieldsCleanNone()
    {
        var results = new List<EngineScanResult>
        {
            EngineScanResult.Success(EngineType.ClamAV, ThreatVerdict.Clean, RiskLevel.None, null, "OK", 80),
            EngineScanResult.Success(EngineType.YARA, ThreatVerdict.Clean, RiskLevel.None, null, "Clean", 20),
            EngineScanResult.Success(EngineType.EMBER_AI, ThreatVerdict.Clean, RiskLevel.None, null, "Probabilité 0.05", 15)
        };

        var (verdict, risk) = VerdictArbitrator.Evaluate(results);

        Assert.AreEqual(ThreatVerdict.Clean, verdict);
        Assert.AreEqual(RiskLevel.None, risk);
    }
}

