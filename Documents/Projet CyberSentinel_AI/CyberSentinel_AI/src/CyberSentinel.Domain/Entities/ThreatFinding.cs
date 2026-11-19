using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Domain.Entities;

public class ThreatFinding
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public EngineType Engine { get; init; }
    public string ThreatName { get; init; } = string.Empty;
    public RiskLevel RiskLevel { get; init; }
    public string Details { get; init; } = string.Empty;
    public DateTime DetectedAt { get; init; } = DateTime.UtcNow;

    public ThreatFinding() { }

    public ThreatFinding(EngineType engine, string threatName, RiskLevel riskLevel, string details)
    {
        Engine = engine;
        ThreatName = threatName;
        RiskLevel = riskLevel;
        Details = details;
        DetectedAt = DateTime.UtcNow;
    }
}

