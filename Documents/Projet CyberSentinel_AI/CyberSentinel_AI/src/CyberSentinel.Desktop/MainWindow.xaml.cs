using System.Windows;
using CyberSentinel.AI.Inference;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.Services;
using CyberSentinel.Desktop.ViewModels;
using CyberSentinel.Infrastructure.Persistence;
using CyberSentinel.Infrastructure.Reporting;
using CyberSentinel.Infrastructure.Security;
using CyberSentinel.Infrastructure.SystemIntegration;
using CyberSentinel.Infrastructure.Vulnerabilities;

namespace CyberSentinel.Desktop;

public partial class MainWindow : Window
{
    public MainViewModel ViewModel { get; }

    public MainWindow()
    {
        InitializeComponent();

        // 1. Module Malware Detection (Antivirus ClamAV + Heuristiques YARA + IA EMBER2024)
        IFileAnalyzer fileAnalyzer = new FileAnalyzer();
        IAntivirusScanner antivirusScanner = new ClamAvScanner();
        IYaraScanner yaraScanner = new YaraScanner();
        IAiMalwareClassifier aiClassifier = new OnnxMalwareInferenceService(useEmber2024: true);
        IScanHistoryRepository historyRepository = new JsonScanHistoryRepository();
        IQuarantineService quarantineService = new QuarantineManager();

        IScanOrchestrator scanOrchestrator = new MalwareScanOrchestrator(
            fileAnalyzer,
            antivirusScanner,
            yaraScanner,
            historyRepository,
            aiClassifier);

        var malwareScannerVm = new MalwareScannerViewModel(scanOrchestrator, quarantineService);

        // 2. Module System Inventory Scanner & Persistance SQLite
        IUpdateManager updateManager = new WinGetManager();
        IVulnerabilityCache vulnCache = new JsonVulnerabilityCache();
        NvdRateLimiter rateLimiter = new NvdRateLimiter(hasApiKey: false);
        IVulnerabilityProvider vulnProvider = new NvdVulnerabilityProvider(vulnCache, rateLimiter);
        WindowsRegistryScanner registryScanner = new WindowsRegistryScanner();

        IInventoryRepository inventoryRepo = new SqliteInventoryRepository();
        ISystemInventoryService inventoryService = new SystemInventoryService(
            registryScanner,
            updateManager,
            new InventoryReconciliationEngine());

        var systemInventoryVm = new SystemInventoryViewModel(inventoryService, inventoryRepo);

        // 3. Module System Vulnerability & Audit Orchestrator
        ISystemAuditOrchestrator auditOrchestrator = new SystemAuditOrchestrator(
            registryScanner,
            vulnProvider,
            updateManager);

        var systemAuditVm = new SystemAuditViewModel(auditOrchestrator, updateManager);

        // 4. Module Vulnerability Center (NVD API 2.0 / CVE / CVSS / OSV)
        IVulnerabilityScannerService vulnScannerService = new VulnerabilityScannerService(
            inventoryService,
            vulnProvider);

        var vulnerabilityCenterVm = new VulnerabilityCenterViewModel(vulnScannerService);

        // 5. Module Update Management (WinGet, Traçabilité & Confirmation de sécurité)
        IUpdateHistoryRepository updateHistoryRepo = new JsonUpdateHistoryRepository();
        IUpdateManagerService updateService = new UpdateManagerService(
            inventoryService,
            vulnProvider,
            updateManager,
            updateHistoryRepo);

        var updateManagerVm = new UpdateManagerViewModel(updateService);

        // 6. Module Dashboard Principal & Reporting Consolidé (Export PDF natif)
        IPdfGenerator pdfGenerator = new PdfReportGenerator();
        IDashboardService dashboardService = new DashboardService(
            historyRepository, 
            inventoryRepo, 
            updateHistoryRepo);

        IReportService reportService = new ReportService(
            historyRepository, 
            inventoryRepo, 
            vulnScannerService, 
            updateService, 
            pdfGenerator);

        var dashboardVm = new DashboardViewModel(
            dashboardService, 
            reportService, 
            vulnScannerService, 
            updateService);

        var scanHistoryVm = new ScanHistoryViewModel(
            historyRepository, 
            reportService);

        // 7. Modèle de vue composite racine
        ViewModel = new MainViewModel(
            dashboardVm,
            malwareScannerVm, 
            systemAuditVm, 
            systemInventoryVm, 
            vulnerabilityCenterVm, 
            updateManagerVm,
            scanHistoryVm);

        DataContext = ViewModel;
    }
}
