namespace CyberSentinel.AI.Features;

public class EmberFeatureVector
{
    public const int ClassicVectorDimension = 2381; // EMBER 2018 (v2)
    public const int Ember2024VectorDimension = 2568; // EMBER2024 (v3 / thrember)

    public float[] Features { get; }
    public int Dimension => Features.Length;

    public EmberFeatureVector(int dimension = ClassicVectorDimension)
    {
        Features = new float[dimension];
    }

    public EmberFeatureVector(float[] features)
    {
        Features = features ?? throw new ArgumentNullException(nameof(features));
    }

    public static EmberFeatureVector Empty(int dimension = ClassicVectorDimension)
    {
        return new EmberFeatureVector(dimension);
    }
}

