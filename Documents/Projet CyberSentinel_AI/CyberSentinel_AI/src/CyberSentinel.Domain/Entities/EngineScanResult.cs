using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Domain.Entities;

public class EngineScanResult
{
    public EngineType Engine { get; init; }
    public ThreatVerdict Verdict { get; init; }
    public RiskLevel RiskLevel { get; init; }
    public string? ThreatName { get; init; }
    public string Details { get; init; } = string.Empty;
    public long DurationMs { get; init; }
    public bool IsSuccess { get; init; } = true;
    public string? ErrorMessage { get; init; }

    public static EngineScanResult Success(EngineType engine, ThreatVerdict verdict, RiskLevel risk, string? threatName, string details, long durationMs)
    {
        return new EngineScanResult
        {
            Engine = engine,
            Verdict = verdict,
            RiskLevel = risk,
            ThreatName = threatName,
            Details = details,
            DurationMs = durationMs,
            IsSuccess = true
        };
    }

    public static EngineScanResult Failure(EngineType engine, string errorMessage, long durationMs = 0)
    {
        return new EngineScanResult
        {
            Engine = engine,
            Verdict = ThreatVerdict.Error,
            RiskLevel = RiskLevel.None,
            ThreatName = null,
            Details = errorMessage,
            DurationMs = durationMs,
            IsSuccess = false,
            ErrorMessage = errorMessage
        };
    }
}

