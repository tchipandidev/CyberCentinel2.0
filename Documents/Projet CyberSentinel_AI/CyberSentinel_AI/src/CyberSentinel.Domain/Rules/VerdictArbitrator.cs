using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Domain.Rules;

/// <summary>
/// Moteur d'arbitrage et de fusion des résultats multi-moteurs (ClamAV, YARA, EMBER2024).
/// Conforme à la règle stricte d'asymétrie de sécurité :
/// Un résultat IA bénin ne peut en aucun cas annuler ou affaiblir une détection antivirale ou YARA déterministe.
/// </summary>
public static class VerdictArbitrator
{
    public static (ThreatVerdict Verdict, RiskLevel Risk) Evaluate(
        IEnumerable<EngineScanResult> results, 
        float aiMalwareThreshold = 0.70f,
        float aiSuspiciousThreshold = 0.30f)
    {
        var resultList = results.ToList();
        if (resultList.Count == 0)
        {
            return (ThreatVerdict.Clean, RiskLevel.None);
        }

        var clamAv = resultList.FirstOrDefault(r => r.Engine == EngineType.ClamAV);
        var yara = resultList.FirstOrDefault(r => r.Engine == EngineType.YARA);
        var ai = resultList.FirstOrDefault(r => r.Engine == EngineType.EMBER_AI);

        // RÈGLE 1 : Priorité absolue à la signature antivirale ClamAV
        if (clamAv != null && clamAv.Verdict == ThreatVerdict.Malicious)
        {
            return (ThreatVerdict.Malicious, RiskLevel.Critical);
        }

        // RÈGLE 2 : Priorité aux correspondances critiques YARA (Ransomware, Credentials dump)
        if (yara != null && yara.Verdict == ThreatVerdict.Malicious)
        {
            return (ThreatVerdict.Malicious, RiskLevel.Critical);
        }

        // RÈGLE 3 : Corrélation croisée YARA Suspicious + IA EMBER
        if (yara != null && yara.Verdict == ThreatVerdict.Suspicious)
        {
            if (ai != null && (ai.Verdict == ThreatVerdict.Malicious || ai.Verdict == ThreatVerdict.Suspicious))
            {
                // Deux moteurs heuristiques indépendants concordants élèvent le niveau en Malveillant
                return (ThreatVerdict.Malicious, RiskLevel.High);
            }
            return (ThreatVerdict.Suspicious, RiskLevel.Medium);
        }

        // RÈGLE 4 : Détection IA EMBER2024 seule (0-day ou nouvelle variante)
        if (ai != null && ai.Verdict == ThreatVerdict.Malicious)
        {
            return (ThreatVerdict.Malicious, RiskLevel.High);
        }

        if (ai != null && ai.Verdict == ThreatVerdict.Suspicious)
        {
            return (ThreatVerdict.Suspicious, RiskLevel.Medium);
        }

        // RÈGLE 5 : Détection générique d'autres moteurs éventuels
        bool hasAnyMalicious = resultList.Any(r => r.Verdict == ThreatVerdict.Malicious);
        if (hasAnyMalicious)
        {
            return (ThreatVerdict.Malicious, RiskLevel.Critical);
        }

        bool hasAnySuspicious = resultList.Any(r => r.Verdict == ThreatVerdict.Suspicious);
        if (hasAnySuspicious)
        {
            return (ThreatVerdict.Suspicious, RiskLevel.Medium);
        }

        // RÈGLE 6 : Tous moteurs en erreur
        if (resultList.All(r => r.Verdict == ThreatVerdict.Error))
        {
            return (ThreatVerdict.Error, RiskLevel.None);
        }

        // RÈGLE 7 : Fichier sain validé
        return (ThreatVerdict.Clean, RiskLevel.None);
    }
}
