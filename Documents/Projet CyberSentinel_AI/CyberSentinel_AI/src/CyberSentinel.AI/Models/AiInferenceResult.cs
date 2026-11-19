namespace CyberSentinel.AI.Models;

public class AiInferenceResult
{
    public AiClassificationVerdict Verdict { get; init; }
    public float RawMalwareProbability { get; init; } // 0.0f à 1.0f
    public float LogitScore { get; init; }
    public float ConfidenceScore { get; init; } // Mesure de la certitude statistique relative
    public float BenignThreshold { get; init; } = 0.30f;
    public float MaliciousThreshold { get; init; } = 0.70f;
    public string ModelName { get; init; } = string.Empty;
    public string ModelVersion { get; init; } = string.Empty;
    public int FeatureVectorDimension { get; init; }
    public long InferenceDurationMs { get; init; }
    public bool IsSuccess { get; init; } = true;
    public string? ErrorMessage { get; init; }
    public List<string> ExplanatoryFactors { get; init; } = new();

    public static AiInferenceResult Unsupported(string reason, string modelName = "EMBER-PE-Engine")
    {
        return new AiInferenceResult
        {
            Verdict = AiClassificationVerdict.UnknownOrUnsupported,
            RawMalwareProbability = 0.0f,
            LogitScore = 0.0f,
            ConfidenceScore = 0.0f,
            ModelName = modelName,
            ModelVersion = "2024.1",
            FeatureVectorDimension = 0,
            InferenceDurationMs = 0,
            IsSuccess = false,
            ErrorMessage = reason,
            ExplanatoryFactors = { reason }
        };
    }
}

