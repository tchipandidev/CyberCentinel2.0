using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows.Input;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.DTOs;
using CyberSentinel.Desktop.Common;

namespace CyberSentinel.Desktop.ViewModels;

public class DashboardViewModel : ViewModelBase
{
    private readonly IDashboardService _dashboardService;
    private readonly IReportService _reportService;
    private readonly IVulnerabilityScannerService _vulnService;
    private readonly IUpdateManagerService _updateService;

    private bool _isLoading;
    private string _statusMessage = "Prêt.";
    private float _securityScore = 100.0f;
    private string _securityVerdict = "Sécurisé (Posture Optimale)";
    private string _postureColor = "#3FB950";

    private int _totalFilesScanned;
    private int _threatsDetectedCount;
    private int _suspiciousFilesCount;
    private int _cleanFilesCount;
    private int _criticalVulnerabilitiesCount;
    private int _highVulnerabilitiesCount;
    private int _availableUpdatesCount;
    private int _criticalUpdatesCount;
    private int _totalInstalledSoftwareCount;

    private string _lastScanDateFormatted = "Aucune analyse récente";
    private string _lastScanTargetPath = "-";
    private string _lastScanVerdict = "N/A";
    private long _lastScanDurationMs;

    private string _selectedTimeFilter = "Tout l'historique";

    public IReadOnlyList<string> TimeFilters { get; } = new[]
    {
        "Tout l'historique", "Dernières 24h", "7 derniers jours", "30 derniers jours"
    };

    public ObservableCollection<ScanSessionSummaryDto> RecentSessions { get; } = new();
    public ObservableCollection<VulnerabilityDto> TopVulnerabilities { get; } = new();
    public ObservableCollection<SoftwareUpdateDto> TopUpdates { get; } = new();

    public bool IsLoading
    {
        get => _isLoading;
        set => SetProperty(ref _isLoading, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public float SecurityScore
    {
        get => _securityScore;
        set => SetProperty(ref _securityScore, value);
    }

    public string SecurityVerdict
    {
        get => _securityVerdict;
        set => SetProperty(ref _securityVerdict, value);
    }

    public string PostureColor
    {
        get => _postureColor;
        set => SetProperty(ref _postureColor, value);
    }

    public int TotalFilesScanned
    {
        get => _totalFilesScanned;
        set => SetProperty(ref _totalFilesScanned, value);
    }

    public int ThreatsDetectedCount
    {
        get => _threatsDetectedCount;
        set => SetProperty(ref _threatsDetectedCount, value);
    }

    public int SuspiciousFilesCount
    {
        get => _suspiciousFilesCount;
        set => SetProperty(ref _suspiciousFilesCount, value);
    }

    public int CleanFilesCount
    {
        get => _cleanFilesCount;
        set => SetProperty(ref _cleanFilesCount, value);
    }

    public int CriticalVulnerabilitiesCount
    {
        get => _criticalVulnerabilitiesCount;
        set => SetProperty(ref _criticalVulnerabilitiesCount, value);
    }

    public int HighVulnerabilitiesCount
    {
        get => _highVulnerabilitiesCount;
        set => SetProperty(ref _highVulnerabilitiesCount, value);
    }

    public int AvailableUpdatesCount
    {
        get => _availableUpdatesCount;
        set => SetProperty(ref _availableUpdatesCount, value);
    }

    public int CriticalUpdatesCount
    {
        get => _criticalUpdatesCount;
        set => SetProperty(ref _criticalUpdatesCount, value);
    }

    public int TotalInstalledSoftwareCount
    {
        get => _totalInstalledSoftwareCount;
        set => SetProperty(ref _totalInstalledSoftwareCount, value);
    }

    public string LastScanDateFormatted
    {
        get => _lastScanDateFormatted;
        set => SetProperty(ref _lastScanDateFormatted, value);
    }

    public string LastScanTargetPath
    {
        get => _lastScanTargetPath;
        set => SetProperty(ref _lastScanTargetPath, value);
    }

    public string LastScanVerdict
    {
        get => _lastScanVerdict;
        set => SetProperty(ref _lastScanVerdict, value);
    }

    public long LastScanDurationMs
    {
        get => _lastScanDurationMs;
        set => SetProperty(ref _lastScanDurationMs, value);
    }

    public string SelectedTimeFilter
    {
        get => _selectedTimeFilter;
        set
        {
            if (SetProperty(ref _selectedTimeFilter, value))
            {
                _ = LoadMetricsAsync();
            }
        }
    }

    // Commandes
    public ICommand RefreshCommand { get; }
    public ICommand ExportPdfCommand { get; }
    public ICommand ExportJsonCommand { get; }

    public DashboardViewModel(
        IDashboardService dashboardService,
        IReportService reportService,
        IVulnerabilityScannerService vulnService,
        IUpdateManagerService updateService)
    {
        _dashboardService = dashboardService ?? throw new ArgumentNullException(nameof(dashboardService));
        _reportService = reportService ?? throw new ArgumentNullException(nameof(reportService));
        _vulnService = vulnService ?? throw new ArgumentNullException(nameof(vulnService));
        _updateService = updateService ?? throw new ArgumentNullException(nameof(updateService));

        RefreshCommand = new RelayCommand(async () => await LoadMetricsAsync());
        ExportPdfCommand = new RelayCommand(async () => await ExportConsolidatedPdfAsync());
        ExportJsonCommand = new RelayCommand(async () => await ExportConsolidatedJsonAsync());

        // Chargement initial
        _ = LoadMetricsAsync();
    }

    public async Task LoadMetricsAsync()
    {
        IsLoading = true;
        StatusMessage = "Actualisation des métriques en temps réel...";

        try
        {
            TimeSpan? window = SelectedTimeFilter switch
            {
                "Dernières 24h" => TimeSpan.FromDays(1),
                "7 derniers jours" => TimeSpan.FromDays(7),
                "30 derniers jours" => TimeSpan.FromDays(30),
                _ => null
            };

            var metrics = await _dashboardService.GetDashboardMetricsAsync(window);

            SecurityScore = metrics.OverallSecurityScore;
            SecurityVerdict = metrics.SecurityPostureVerdict;
            PostureColor = metrics.PostureColor;

            TotalFilesScanned = metrics.TotalFilesScanned;
            ThreatsDetectedCount = metrics.ThreatsDetectedCount;
            SuspiciousFilesCount = metrics.SuspiciousFilesCount;
            CleanFilesCount = metrics.CleanFilesCount;

            TotalInstalledSoftwareCount = metrics.TotalInstalledSoftwareCount;
            LastScanDateFormatted = metrics.FormattedLastScanDate;
            LastScanTargetPath = metrics.LastScanTargetPath;
            LastScanVerdict = metrics.LastScanVerdict;
            LastScanDurationMs = metrics.LastScanDurationMs;

            RecentSessions.Clear();
            foreach (var session in metrics.RecentSessions)
            {
                RecentSessions.Add(session);
            }

            // Récupérer les vulnérabilités actives
            try
            {
                var vulns = await _vulnService.ScanVulnerabilitiesAsync();
                CriticalVulnerabilitiesCount = vulns.Count(v => v.Severity == Domain.Enums.CvssSeverity.Critical);
                HighVulnerabilitiesCount = vulns.Count(v => v.Severity == Domain.Enums.CvssSeverity.High);

                TopVulnerabilities.Clear();
                foreach (var v in vulns.Take(5))
                {
                    TopVulnerabilities.Add(v);
                }
            }
            catch { }

            // Récupérer les mises à jour
            try
            {
                var updates = await _updateService.CheckUpdatesAsync();
                AvailableUpdatesCount = updates.Count(u => u.IsAvailable);
                CriticalUpdatesCount = updates.Count(u => u.HasCriticalSecurityPatch && u.IsAvailable);

                TopUpdates.Clear();
                foreach (var u in updates.Where(x => x.IsAvailable).Take(5))
                {
                    TopUpdates.Add(u);
                }
            }
            catch { }

            StatusMessage = "Tableau de bord synchronisé avec les données du système.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Erreur d'actualisation : {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    private async Task ExportConsolidatedPdfAsync()
    {
        StatusMessage = "Génération du rapport d'audit PDF en cours...";
        try
        {
            var report = await _reportService.GenerateFullReportAsync();
            string path = await _reportService.ExportReportToPdfAsync(report);
            StatusMessage = $"Rapport PDF exporté avec succès : {path}";

            // Ouvrir automatiquement le document PDF dans le visualiseur par défaut
            Process.Start(new ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            StatusMessage = $"Échec de l'export PDF : {ex.Message}";
        }
    }

    private async Task ExportConsolidatedJsonAsync()
    {
        StatusMessage = "Génération du rapport JSON en cours...";
        try
        {
            var report = await _reportService.GenerateFullReportAsync();
            string path = await _reportService.ExportReportToJsonAsync(report);
            StatusMessage = $"Rapport JSON exporté avec succès : {path}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Échec de l'export JSON : {ex.Message}";
        }
    }
}

