using CyberSentinel.Desktop.Common;

namespace CyberSentinel.Desktop.ViewModels;

public class MainViewModel : ViewModelBase
{
    public DashboardViewModel Dashboard { get; }
    public MalwareScannerViewModel Scanner { get; }
    public SystemInventoryViewModel Inventory { get; }
    public VulnerabilityCenterViewModel Vulnerabilities { get; }
    public UpdateManagerViewModel Updates { get; }
    public SystemAuditViewModel Audit { get; }
    public ScanHistoryViewModel History { get; }

    public MainViewModel(
        DashboardViewModel dashboard,
        MalwareScannerViewModel scanner, 
        SystemAuditViewModel audit,
        SystemInventoryViewModel inventory,
        VulnerabilityCenterViewModel vulnerabilities,
        UpdateManagerViewModel updates,
        ScanHistoryViewModel history)
    {
        Dashboard = dashboard ?? throw new ArgumentNullException(nameof(dashboard));
        Scanner = scanner ?? throw new ArgumentNullException(nameof(scanner));
        Audit = audit ?? throw new ArgumentNullException(nameof(audit));
        Inventory = inventory ?? throw new ArgumentNullException(nameof(inventory));
        Vulnerabilities = vulnerabilities ?? throw new ArgumentNullException(nameof(vulnerabilities));
        Updates = updates ?? throw new ArgumentNullException(nameof(updates));
        History = history ?? throw new ArgumentNullException(nameof(history));
    }
}
