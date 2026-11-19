using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CyberSentinel.Infrastructure.Persistence.Entities;

[Table("InventorySessions")]
public class InventorySessionEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public DateTime SnapshotDate { get; set; } = DateTime.UtcNow;

    public int TotalApplicationsCount { get; set; }
    public int X64ApplicationsCount { get; set; }
    public int X86ApplicationsCount { get; set; }
    public int OtherArchCount { get; set; }

    [MaxLength(100)]
    public string MachineName { get; set; } = string.Empty;

    [MaxLength(200)]
    public string OsVersion { get; set; } = string.Empty;

    public ICollection<InstalledSoftwareEntity> Applications { get; set; } = new List<InstalledSoftwareEntity>();
}

[Table("InstalledSoftware")]
public class InstalledSoftwareEntity
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public Guid SessionId { get; set; }

    [ForeignKey(nameof(SessionId))]
    public InventorySessionEntity? Session { get; set; }

    [Required]
    [MaxLength(255)]
    public string DisplayName { get; set; } = string.Empty;

    [MaxLength(255)]
    public string Publisher { get; set; } = "Éditeur inconnu";

    [MaxLength(100)]
    public string DisplayVersion { get; set; } = "Non spécifiée";

    [MaxLength(20)]
    public string Architecture { get; set; } = "Unknown";

    public DateTime? InstallDate { get; set; }

    [MaxLength(500)]
    public string InstallLocation { get; set; } = string.Empty;

    [MaxLength(100)]
    public string IdentificationSource { get; set; } = string.Empty;

    [MaxLength(150)]
    public string? PackageIdentifier { get; set; }

    [MaxLength(255)]
    public string? CanonicalCpe { get; set; }

    public bool IsSystemComponent { get; set; }

    public DateTime DiscoveredAt { get; set; } = DateTime.UtcNow;
}

