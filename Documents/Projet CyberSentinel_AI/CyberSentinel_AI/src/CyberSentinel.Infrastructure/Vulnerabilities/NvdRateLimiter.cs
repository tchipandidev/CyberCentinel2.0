namespace CyberSentinel.Infrastructure.Vulnerabilities;

/// <summary>
/// Gestionnaire d'étranglement de requêtes (Sliding-Window Token Bucket) 
/// conforme aux spécifications officielles de l'API NIST NVD 2.0.
/// - Sans clé API : 5 requêtes par fenêtre glissante de 30 secondes (intervalle min conseillé ~6s).
/// - Avec clé API : 50 requêtes par fenêtre glissante de 30 secondes (intervalle min conseillé ~0.6s).
/// </summary>
public class NvdRateLimiter
{
    private readonly SemaphoreSlim _semaphore = new(1, 1);
    private readonly Queue<DateTime> _requestTimestamps = new();
    private readonly int _maxRequestsPerWindow;
    private readonly TimeSpan _windowDuration;
    private readonly TimeSpan _minIntervalBetweenRequests;

    public int MaxRequestsPerWindow => _maxRequestsPerWindow;
    public TimeSpan WindowDuration => _windowDuration;
    public TimeSpan MinIntervalBetweenRequests => _minIntervalBetweenRequests;

    public NvdRateLimiter(bool hasApiKey = false)
        : this(hasApiKey ? 50 : 5, TimeSpan.FromSeconds(30), TimeSpan.FromMilliseconds(hasApiKey ? 600 : 6000))
    {
    }

    public NvdRateLimiter(int maxRequestsPerWindow, TimeSpan windowDuration, TimeSpan minIntervalBetweenRequests)
    {
        if (maxRequestsPerWindow <= 0) throw new ArgumentOutOfRangeException(nameof(maxRequestsPerWindow));
        if (windowDuration <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(windowDuration));

        _maxRequestsPerWindow = maxRequestsPerWindow;
        _windowDuration = windowDuration;
        _minIntervalBetweenRequests = minIntervalBetweenRequests;
    }

    public int GetActiveRequestCountInWindow()
    {
        var now = DateTime.UtcNow;
        lock (_requestTimestamps)
        {
            while (_requestTimestamps.Count > 0 && (now - _requestTimestamps.Peek()) > _windowDuration)
            {
                _requestTimestamps.Dequeue();
            }
            return _requestTimestamps.Count;
        }
    }

    public async Task WaitForPermitAsync(CancellationToken cancellationToken = default)
    {
        await _semaphore.WaitAsync(cancellationToken);
        try
        {
            var now = DateTime.UtcNow;

            // 1. Purge des requêtes antérieures à la fenêtre glissante
            while (_requestTimestamps.Count > 0 && (now - _requestTimestamps.Peek()) > _windowDuration)
            {
                _requestTimestamps.Dequeue();
            }

            // 2. Si le quota de la fenêtre glissante est atteint, attendre l'expiration de la plus ancienne
            if (_requestTimestamps.Count >= _maxRequestsPerWindow)
            {
                var oldestRequest = _requestTimestamps.Peek();
                var waitTime = _windowDuration - (now - oldestRequest);
                if (waitTime > TimeSpan.Zero)
                {
                    await Task.Delay(waitTime, cancellationToken);
                    now = DateTime.UtcNow;
                    while (_requestTimestamps.Count > 0 && (now - _requestTimestamps.Peek()) > _windowDuration)
                    {
                        _requestTimestamps.Dequeue();
                    }
                }
            }

            // 3. Délai de sécurité minimal entre deux requêtes consécutives pour éviter les bursts
            if (_requestTimestamps.Count > 0)
            {
                var lastRequest = _requestTimestamps.Last();
                var elapsedSinceLast = now - lastRequest;
                if (elapsedSinceLast < _minIntervalBetweenRequests)
                {
                    var throttleDelay = _minIntervalBetweenRequests - elapsedSinceLast;
                    await Task.Delay(throttleDelay, cancellationToken);
                }
            }

            _requestTimestamps.Enqueue(DateTime.UtcNow);
        }
        finally
        {
            _semaphore.Release();
        }
    }
}
