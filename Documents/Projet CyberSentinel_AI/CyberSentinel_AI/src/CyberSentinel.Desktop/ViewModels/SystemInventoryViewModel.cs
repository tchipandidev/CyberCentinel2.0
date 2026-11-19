using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Input;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.DTOs;
using CyberSentinel.Desktop.Common;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;
using Microsoft.Win32;

namespace CyberSentinel.Desktop.ViewModels;

public class SystemInventoryViewModel : ViewModelBase
{
    private readonly ISystemInventoryService _inventoryService;
    private readonly IInventoryRepository _inventoryRepository;
    private CancellationTokenSource? _scanCts;

    private bool _isScanning;
    private string _scanStatus = "Prêt. Cliquez sur 'Lancer l'Inventaire' pour analyser les logiciels installés.";
    private int _scanProgress;
    private string _searchText = string.Empty;
    private string _selectedArchitectureFilter = "Tous";
    private bool _filterOnlyWithUpdates;
    private bool _filterOnlyWithVulnerabilities;
    private InstalledApplicationDto? _selectedApplication;

    private int _totalApplicationsCount;
    private int _x64Count;
    private int _x86Count;
    private int _knownPublisherCount;
    private int _knownVersionCount;

    public ObservableCollection<InstalledApplicationDto> AllApplications { get; } = new();
    public ObservableCollection<InstalledApplicationDto> FilteredApplications { get; } = new();

    public bool IsScanning
    {
        get => _isScanning;
        set
        {
            if (SetProperty(ref _isScanning, value))
            {
                OnPropertyChanged(nameof(CanStartScan));
                OnPropertyChanged(nameof(CanCancelScan));
            }
        }
    }

    public bool CanStartScan => !IsScanning;
    public bool CanCancelScan => IsScanning;

    public string ScanStatus
    {
        get => _scanStatus;
        set => SetProperty(ref _scanStatus, value);
    }

    public int ScanProgress
    {
        get => _scanProgress;
        set => SetProperty(ref _scanProgress, value);
    }

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetProperty(ref _searchText, value))
            {
                ApplyFilter();
            }
        }
    }

    public string SelectedArchitectureFilter
    {
        get => _selectedArchitectureFilter;
        set
        {
            if (SetProperty(ref _selectedArchitectureFilter, value))
            {
                ApplyFilter();
            }
        }
    }

    public bool FilterOnlyWithUpdates
    {
        get => _filterOnlyWithUpdates;
        set
        {
            if (SetProperty(ref _filterOnlyWithUpdates, value))
            {
                ApplyFilter();
            }
        }
    }

    public bool FilterOnlyWithVulnerabilities
    {
        get => _filterOnlyWithVulnerabilities;
        set
        {
            if (SetProperty(ref _filterOnlyWithVulnerabilities, value))
            {
                ApplyFilter();
            }
        }
    }

    public InstalledApplicationDto? SelectedApplication
    {
        get => _selectedApplication;
        set => SetProperty(ref _selectedApplication, value);
    }

    public int TotalApplicationsCount
    {
        get => _totalApplicationsCount;
        set => SetProperty(ref _totalApplicationsCount, value);
    }

    public int X64Count
    {
        get => _x64Count;
        set => SetProperty(ref _x64Count, value);
    }

    public int X86Count
    {
        get => _x86Count;
        set => SetProperty(ref _x86Count, value);
    }

    public int KnownPublisherCount
    {
        get => _knownPublisherCount;
        set => SetProperty(ref _knownPublisherCount, value);
    }

    public int KnownVersionCount
    {
        get => _knownVersionCount;
        set => SetProperty(ref _knownVersionCount, value);
    }

    public ICommand ScanInventoryCommand { get; }
    public ICommand CancelScanCommand { get; }
    public ICommand ClearSearchCommand { get; }
    public ICommand ExportCsvCommand { get; }

    public SystemInventoryViewModel(
        ISystemInventoryService inventoryService,
        IInventoryRepository inventoryRepository)
    {
        _inventoryService = inventoryService ?? throw new ArgumentNullException(nameof(inventoryService));
        _inventoryRepository = inventoryRepository ?? throw new ArgumentNullException(nameof(inventoryRepository));

        ScanInventoryCommand = new AsyncRelayCommand(ScanInventoryAsync, () => CanStartScan);
        CancelScanCommand = new RelayCommand(CancelScan, () => CanCancelScan);
        ClearSearchCommand = new RelayCommand(() => SearchText = string.Empty);
        ExportCsvCommand = new RelayCommand(ExportCsv, () => FilteredApplications.Count > 0);
    }

    public async Task ScanInventoryAsync()
    {
        if (IsScanning) return;

        IsScanning = true;
        ScanProgress = 0;
        ScanStatus = "Démarrage de l'analyse du parc applicatif...";
        _scanCts = new CancellationTokenSource();

        try
        {
            var progressHandler = new Progress<(string Step, int Percent)>(report =>
            {
                System.Windows.Application.Current?.Dispatcher.Invoke(() =>
                {
                    ScanStatus = report.Step;
                    ScanProgress = report.Percent;
                });
            });

            var apps = await _inventoryService.GetInstalledApplicationsAsync(progressHandler, _scanCts.Token);

            AllApplications.Clear();
            foreach (var app in apps)
            {
                AllApplications.Add(MapToDto(app));
            }

            // Calcul des indicateurs statistiques
            TotalApplicationsCount = apps.Count;
            X64Count = apps.Count(a => a.Architecture == AppArchitecture.X64);
            X86Count = apps.Count(a => a.Architecture == AppArchitecture.X86);
            KnownPublisherCount = apps.Count(a => a.HasKnownPublisher);
            KnownVersionCount = apps.Count(a => a.HasKnownVersion);

            // Persistance de l'instantané (Snapshot SQLite / Journal)
            var session = new InventorySession
            {
                TotalApplicationsCount = TotalApplicationsCount,
                X64ApplicationsCount = X64Count,
                X86ApplicationsCount = X86Count,
                OtherArchCount = TotalApplicationsCount - (X64Count + X86Count),
                Applications = apps.ToList()
            };
            await _inventoryRepository.SaveInventorySessionAsync(session, _scanCts.Token);

            ApplyFilter();
            ScanStatus = $"Inventaire terminé : {apps.Count} applications réconciliées et enregistrées en base locale.";
        }
        catch (OperationCanceledException)
        {
            ScanStatus = "Inventaire système annulé par l'utilisateur.";
        }
        catch (Exception ex)
        {
            ScanStatus = $"Erreur lors de l'inventaire : {ex.Message}";
            MessageBox.Show($"Une erreur est survenue lors de l'inventaire :\r\n{ex.Message}", "Erreur Système", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsScanning = false;
            _scanCts?.Dispose();
            _scanCts = null;
        }
    }

    public void CancelScan()
    {
        if (_scanCts != null && !_scanCts.IsCancellationRequested)
        {
            ScanStatus = "Annulation en cours...";
            _scanCts.Cancel();
        }
    }

    public void ApplyFilter()
    {
        FilteredApplications.Clear();

        var query = AllApplications.AsEnumerable();

        // 1. Filtre par recherche textuelle
        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            string search = SearchText.Trim();
            query = query.Where(a =>
                a.DisplayName.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                a.Publisher.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                (a.PackageIdentifier != null && a.PackageIdentifier.Contains(search, StringComparison.OrdinalIgnoreCase)) ||
                a.InstallLocation.Contains(search, StringComparison.OrdinalIgnoreCase));
        }

        // 2. Filtre par architecture
        if (SelectedArchitectureFilter == "64-bit")
        {
            query = query.Where(a => a.Architecture == AppArchitecture.X64);
        }
        else if (SelectedArchitectureFilter == "32-bit")
        {
            query = query.Where(a => a.Architecture == AppArchitecture.X86);
        }
        else if (SelectedArchitectureFilter == "Autres / Neutre")
        {
            query = query.Where(a => a.Architecture != AppArchitecture.X64 && a.Architecture != AppArchitecture.X86);
        }

        // 3. Filtre avec mise à jour disponible
        if (FilterOnlyWithUpdates)
        {
            query = query.Where(a => a.HasUpdateAvailable);
        }

        // 4. Filtre avec vulnérabilités
        if (FilterOnlyWithVulnerabilities)
        {
            query = query.Where(a => a.HasVulnerabilities);
        }

        foreach (var item in query)
        {
            FilteredApplications.Add(item);
        }
    }

    public void ExportCsv()
    {
        if (FilteredApplications.Count == 0) return;

        var saveDialog = new SaveFileDialog
        {
            Filter = "Fichiers CSV (*.csv)|*.csv",
            FileName = $"Inventaire_CyberSentinel_{DateTime.Now:yyyyMMdd_HHmm}.csv"
        };

        if (saveDialog.ShowDialog() == true)
        {
            try
            {
                using var writer = new StreamWriter(saveDialog.FileName, false, System.Text.Encoding.UTF8);
                writer.WriteLine("Nom;Éditeur;Version;Architecture;Date Installation;Source;WinGet ID;Emplacement");
                foreach (var a in FilteredApplications)
                {
                    writer.WriteLine($"\"{EscapeCsv(a.DisplayName)}\";\"{EscapeCsv(a.Publisher)}\";\"{EscapeCsv(a.DisplayVersion)}\";\"{a.ArchitectureBadge}\";\"{a.FormattedInstallDate}\";\"{EscapeCsv(a.IdentificationSource)}\";\"{EscapeCsv(a.PackageIdentifier ?? string.Empty)}\";\"{EscapeCsv(a.InstallLocation)}\"");
                }
                MessageBox.Show("Inventaire exporté avec succès au format CSV.", "Export Réussi", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Erreur lors de l'export CSV : {ex.Message}", "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private static string EscapeCsv(string val) => val.Replace("\"", "\"\"");

    private static InstalledApplicationDto MapToDto(InstalledApplication app)
    {
        return new InstalledApplicationDto
        {
            Id = app.Id,
            DisplayName = app.DisplayName,
            Publisher = app.Publisher,
            DisplayVersion = app.DisplayVersion,
            Architecture = app.Architecture,
            InstallDate = app.InstallDate,
            InstallLocation = app.InstallLocation,
            IdentificationSource = app.IdentificationSource,
            RegistryHive = app.RegistryHive,
            PackageIdentifier = app.PackageIdentifier,
            CanonicalCpe = app.CanonicalCpe,
            IsSystemComponent = app.IsSystemComponent,
            AvailableUpdate = app.AvailableUpdate != null ? new SoftwareUpdateDto
            {
                PackageIdentifier = app.AvailableUpdate.PackageIdentifier,
                ApplicationName = app.DisplayName,
                CurrentVersion = app.AvailableUpdate.CurrentVersion,
                AvailableVersion = app.AvailableUpdate.AvailableVersion,
                Status = app.AvailableUpdate.Status
            } : null
        };
    }
}

