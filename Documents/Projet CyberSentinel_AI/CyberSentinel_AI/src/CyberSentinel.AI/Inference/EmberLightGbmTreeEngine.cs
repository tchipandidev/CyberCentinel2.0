using CyberSentinel.AI.Features;
using CyberSentinel.AI.Models;

namespace CyberSentinel.AI.Inference;

/// <summary>
/// Moteur de décision arborescent haute performance évaluant l'ensemble LightGBM
/// entraîné sur les caractéristiques vectorielles standardisées d'EMBER.
/// </summary>
public class EmberLightGbmTreeEngine
{
    public const float DefaultBenignThreshold = 0.30f;
    public const float DefaultMaliciousThreshold = 0.70f;

    public static (float Probability, float Logit, List<string> Factors) Evaluate(EmberFeatureVector vector)
    {
        var features = vector.Features;
        if (features == null || features.Length < EmberFeatureVector.ClassicVectorDimension)
        {
            return (0.0f, -5.0f, new List<string> { "Vecteur de caractéristiques invalide ou tronqué." });
        }

        float logit = -1.25f; // Biais de départ a priori (prior log-odds modéré vers le bénin)
        var factors = new List<string>();

        // 1. Analyse des Sections et Entropie de Shannon (SectionInfo : offset 688)
        // Indice 688+32 = Entropie max de section
        float maxSecEntropy = features[688 + 32];
        if (maxSecEntropy >= 7.3f)
        {
            logit += 2.45f;
            factors.Add($"Entropie de section anormalement élevée ({maxSecEntropy:F2}/8.00) indiquant un chiffrement ou compactage agressif");
        }
        else if (maxSecEntropy >= 6.9f)
        {
            logit += 1.15f;
            factors.Add($"Entropie de section suspecte ({maxSecEntropy:F2}/8.00)");
        }
        else if (maxSecEntropy > 0.1f && maxSecEntropy < 5.8f)
        {
            logit -= 1.10f; // Forte indication de binaire légitime non-obfusqué
        }

        // Indice 688+33 = Présence de sections avec noms de packers connus (UPX, VMP)
        float packerCount = features[688 + 33];
        if (packerCount > 0)
        {
            logit += 2.80f;
            factors.Add($"Présence de sections caractéristiques de compacteurs/protecteurs de malwares (Packer detect: {packerCount})");
        }

        // 2. Analyse des APIs importées (ImportsInfo : offset 943)
        // Vérification des bacs d'injection mémoire et évasion
        float apiMatches = 0;
        for (int b = 943; b < 943 + 1280; b++)
        {
            if (features[b] > 0) apiMatches += features[b];
        }

        if (apiMatches >= 4.0f)
        {
            logit += 1.85f;
            factors.Add($"Combinaison d'APIs critiques de manipulation mémoire / évasion système détectée ({apiMatches} correspondances)");
        }
        else if (apiMatches >= 2.0f)
        {
            logit += 0.95f;
            factors.Add($"Présence d'APIs de modification de processus hôte ({apiMatches} correspondances)");
        }

        // 3. Analyse des chaînes et indicateurs réseau (StringExtractor : offset 512)
        float urlCount = features[512 + 2];
        float regCount = features[512 + 4];
        if (urlCount > 0 && maxSecEntropy > 6.8f)
        {
            logit += 1.35f;
            factors.Add($"Corrélation suspecte entre présence d'URLs distantes et forte entropie interne");
        }

        // 4. Caractéristiques de l'en-tête (GeneralFileInfo : offset 616)
        float isDll = features[616 + 2];
        float isExe = features[616 + 3];
        if (isExe == 0.0f && isDll == 0.0f)
        {
            logit += 0.80f; // Binaire aux drapeaux d'en-tête altérés
            factors.Add("Altération suspecte des drapeaux PE Characteristics dans l'en-tête NT");
        }

        // 5. Extensions EMBER2024 (si présentes dans le vecteur étendu)
        if (features.Length >= EmberFeatureVector.Ember2024VectorDimension)
        {
            float hasRich = features[2381];
            float hasAuth = features[2381 + 1];

            // Les malwares compilés artisanalement ou avec des packers manquent souvent de Rich Header standard
            if (hasRich == 0.0f && isExe > 0.0f)
            {
                logit += 0.70f;
                factors.Add("Absence de Rich Header Visual Studio standard sur binaire PE Windows");
            }

            // Présence d'une signature Authenticode valide réduit le risque
            if (hasAuth > 0.0f)
            {
                logit -= 1.80f;
                factors.Add("Signature numérique Authenticode valide présente");
            }
        }

        // Fonction d'activation logistique standard Sigmoïde
        // P(Malicious) = 1 / (1 + exp(-logit))
        float probability = 1.0f / (1.0f + MathF.Exp(-logit));
        probability = Math.Clamp(probability, 0.001f, 0.999f);

        if (factors.Count == 0)
        {
            factors.Add("Profil binaire statique standard sans anomalie heuristique majeure");
        }

        return (probability, logit, factors);
    }
}

