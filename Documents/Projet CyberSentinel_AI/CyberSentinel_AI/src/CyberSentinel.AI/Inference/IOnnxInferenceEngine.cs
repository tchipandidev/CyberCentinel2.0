using CyberSentinel.AI.Features;
using CyberSentinel.AI.Models;

namespace CyberSentinel.AI.Inference;

public interface IOnnxInferenceEngine : IDisposable
{
    string ModelName { get; }
    string ModelVersion { get; }
    int ExpectedFeatureDimension { get; }
    bool IsModelLoaded { get; }

    Task<bool> LoadModelAsync(string modelPath, CancellationToken cancellationToken = default);
    Task<AiInferenceResult> PredictAsync(EmberFeatureVector featureVector, CancellationToken cancellationToken = default);
    void Unload();
}

