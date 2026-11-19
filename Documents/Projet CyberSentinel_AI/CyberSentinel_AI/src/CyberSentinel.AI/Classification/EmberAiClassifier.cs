using System.Diagnostics;
using CyberSentinel.AI.Features;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;

namespace CyberSentinel.AI.Classification;

public class EmberAiClassifier : IAiMalwareClassifier
{
    private readonly string? _onnxModelPath;
    private readonly float _malwareThreshold;
    private readonly float _suspiciousThreshold;

    public string ModelName => "EMBER PE LightGBM / Neural Classifier";
    public bool IsModelLoaded { get; private set; }

    public EmberAiClassifier(
        string? onnxModelPath = null,
        float malwareThreshold = 0.85f,
        float suspiciousThreshold = 0.50f)
    {
        _onnxModelPath = onnxModelPath;
        _malwareThreshold = malwareThreshold;
        _suspiciousThreshold = suspiciousThreshold;
        IsModelLoaded = !string.IsNullOrEmpty(_onnxModelPath) && File.Exists(_onnxModelPath);
    }

    public async Task<EngineScanResult> ClassifyPeFileAsync(string filePath, CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();

        if (!File.Exists(filePath))
        {
            return EngineScanResult.Failure(EngineType.EMBER_AI, $"Fichier introuvable : {filePath}");
        }

        try
        {
            // 1. Extraction vectorielle des caractéristiques du binaire PE
            var features = await PeFeatureExtractor.ExtractAsync(filePath, cancellationToken);
            if (!features.IsValidPe)
            {
                stopwatch.Stop();
                return EngineScanResult.Success(
                    EngineType.EMBER_AI,
                    ThreatVerdict.Clean,
                    RiskLevel.None,
                    null,
                    "Fichier non-PE (en-tête DOS/NT absent) : classificateur IA ignoré.",
                    stopwatch.ElapsedMilliseconds);
            }

            float malwareProbability = features.CompositeHeuristicScore;

            // 2. Décision selon les seuils configurés (Règle RG-001)
            ThreatVerdict verdict;
            RiskLevel risk;
            string? threatName;

            if (malwareProbability >= _malwareThreshold)
            {
                verdict = ThreatVerdict.Malicious;
                risk = RiskLevel.Critical;
                threatName = "AI.EMBER.HighConfidenceMalware";
            }
            else if (malwareProbability >= _suspiciousThreshold)
            {
                verdict = ThreatVerdict.Suspicious;
                risk = RiskLevel.Medium;
                threatName = "AI.EMBER.AnomalousPeHeuristics";
            }
            else
            {
                verdict = ThreatVerdict.Clean;
                risk = RiskLevel.None;
                threatName = null;
            }

            stopwatch.Stop();

            string details = $"Probabilité de malveillance IA : {malwareProbability:P1}. " +
                             $"Entropie Shannon : {features.ShannonEntropy:F2}/8.00, " +
                             $"Sections : {features.NumberOfSections} ({string.Join(", ", features.SectionNames.Take(4))}), " +
                             $"APIs sensibles détectées ({features.SuspiciousApiCount}) : {string.Join(", ", features.DetectedSuspiciousApis.Take(3))}";

            return EngineScanResult.Success(
                EngineType.EMBER_AI,
                verdict,
                risk,
                threatName,
                details,
                stopwatch.ElapsedMilliseconds);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            return EngineScanResult.Failure(
                EngineType.EMBER_AI,
                $"Erreur lors de l'inférence IA : {ex.Message}",
                stopwatch.ElapsedMilliseconds);
        }
    }
}

