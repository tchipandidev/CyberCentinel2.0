namespace CyberSentinel.Domain.Entities;

public class InventorySession
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public DateTime SnapshotDate { get; init; } = DateTime.UtcNow;
    public int TotalApplicationsCount { get; set; }
    public int X64ApplicationsCount { get; set; }
    public int X86ApplicationsCount { get; set; }
    public int OtherArchCount { get; set; }
    public string MachineName { get; init; } = Environment.MachineName;
    public string OsVersion { get; init; } = Environment.OSVersion.VersionString;

    public List<InstalledApplication> Applications { get; init; } = new();
}

