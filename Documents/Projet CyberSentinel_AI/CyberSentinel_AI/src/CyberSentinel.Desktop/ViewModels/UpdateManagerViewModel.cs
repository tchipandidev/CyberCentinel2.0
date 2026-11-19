using System.Collections.ObjectModel;
using System.Text;
using System.Windows.Input;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.DTOs;
using CyberSentinel.Desktop.Common;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Desktop.ViewModels;

public class UpdateManagerViewModel : ViewModelBase
{
    private readonly IUpdateManagerService _updateService;
    private CancellationTokenSource? _operationCts;

    private bool _isChecking;
    private bool _isUpgrading;
    private int _progressPercent;
    private string _statusMessage = "Prêt à vérifier les mises à jour logicielles.";
    private string _searchText = string.Empty;
    private string _selectedFilter = "Toutes";
    private SoftwareUpdateDto? _selectedUpdate;
    private string _consoleOutput = "CyberSentinel AI - WinGet Update Manager initialisé.\r\n";

    // Modale de confirmation de sécurité
    private bool _isConfirmationOpen;
    private string _confirmationTitle = string.Empty;
    private string _confirmationMessage = string.Empty;
    private Func<Task>? _pendingConfirmedAction;

    public ObservableCollection<SoftwareUpdateDto> AllUpdates { get; } = new();
    public ObservableCollection<SoftwareUpdateDto> FilteredUpdates { get; } = new();
    public ObservableCollection<UpdateHistoryRecord> UpdateHistory { get; } = new();

    public IReadOnlyList<string> FilterOptions { get; } = new[]
    {
        "Toutes", "Sécurité Critique", "Mises à jour dispo", "À jour"
    };

    public bool IsChecking
    {
        get => _isChecking;
        set
        {
            if (SetProperty(ref _isChecking, value))
            {
                OnPropertyChanged(nameof(IsBusy));
                OnPropertyChanged(nameof(CanCheckUpdates));
                OnPropertyChanged(nameof(CanUpgradeSelected));
                OnPropertyChanged(nameof(CanUpgradeAll));
            }
        }
    }

    public bool IsUpgrading
    {
        get => _isUpgrading;
        set
        {
            if (SetProperty(ref _isUpgrading, value))
            {
                OnPropertyChanged(nameof(IsBusy));
                OnPropertyChanged(nameof(CanCheckUpdates));
                OnPropertyChanged(nameof(CanUpgradeSelected));
                OnPropertyChanged(nameof(CanUpgradeAll));
            }
        }
    }

    public bool IsBusy => IsChecking || IsUpgrading;
    public bool CanCheckUpdates => !IsBusy;
    public bool CanUpgradeSelected => !IsBusy && SelectedUpdate != null && SelectedUpdate.IsAvailable;
    public bool CanUpgradeAll => !IsBusy && AllUpdates.Any(u => u.IsAvailable);

    public int ProgressPercent
    {
        get => _progressPercent;
        set => SetProperty(ref _progressPercent, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetProperty(ref _searchText, value))
            {
                ApplyFilters();
            }
        }
    }

    public string SelectedFilter
    {
        get => _selectedFilter;
        set
        {
            if (SetProperty(ref _selectedFilter, value))
            {
                ApplyFilters();
            }
        }
    }

    public SoftwareUpdateDto? SelectedUpdate
    {
        get => _selectedUpdate;
        set
        {
            if (SetProperty(ref _selectedUpdate, value))
            {
                OnPropertyChanged(nameof(HasSelectedUpdate));
                OnPropertyChanged(nameof(CanUpgradeSelected));
            }
        }
    }

    public bool HasSelectedUpdate => SelectedUpdate != null;

    public string ConsoleOutput
    {
        get => _consoleOutput;
        set => SetProperty(ref _consoleOutput, value);
    }

    public string WinGetInfo => $"WinGet: {_updateService.WinGetVersion} | Admin: {(_updateService.IsAdministrator ? "OUI (Élevé)" : "NON (Standard)")}";
    public bool IsAdministrator => _updateService.IsAdministrator;

    // Modale de confirmation
    public bool IsConfirmationOpen
    {
        get => _isConfirmationOpen;
        set => SetProperty(ref _isConfirmationOpen, value);
    }

    public string ConfirmationTitle
    {
        get => _confirmationTitle;
        set => SetProperty(ref _confirmationTitle, value);
    }

    public string ConfirmationMessage
    {
        get => _confirmationMessage;
        set => SetProperty(ref _confirmationMessage, value);
    }

    // Métriques KPI
    public int TotalUpdatesCount => AllUpdates.Count(u => u.IsAvailable);
    public int CriticalSecurityCount => AllUpdates.Count(u => u.HasCriticalSecurityPatch && u.IsAvailable);
    public int UpToDateCount => AllUpdates.Count(u => !u.IsAvailable || u.Status == UpdateStatus.UpToDate);
    public int HistoryCount => UpdateHistory.Count;

    // Commandes
    public ICommand CheckUpdatesCommand { get; }
    public ICommand UpgradeSelectedCommand { get; }
    public ICommand UpgradeAllCommand { get; }
    public ICommand ConfirmActionCommand { get; }
    public ICommand DismissConfirmationCommand { get; }
    public ICommand CancelOperationCommand { get; }
    public ICommand ClearLogsCommand { get; }
    public ICommand RefreshHistoryCommand { get; }

    public UpdateManagerViewModel(IUpdateManagerService updateService)
    {
        _updateService = updateService ?? throw new ArgumentNullException(nameof(updateService));

        CheckUpdatesCommand = new RelayCommand(async () => await CheckUpdatesAsync(), () => CanCheckUpdates);
        UpgradeSelectedCommand = new RelayCommand(RequestUpgradeSelected, () => CanUpgradeSelected);
        UpgradeAllCommand = new RelayCommand(RequestUpgradeAll, () => CanUpgradeAll);
        ConfirmActionCommand = new RelayCommand(async () => await ExecuteConfirmedActionAsync());
        DismissConfirmationCommand = new RelayCommand(DismissConfirmation);
        CancelOperationCommand = new RelayCommand(CancelOperation, () => IsBusy);
        ClearLogsCommand = new RelayCommand(ClearLogs);
        RefreshHistoryCommand = new RelayCommand(async () => await LoadHistoryAsync());
    }

    public async Task CheckUpdatesAsync()
    {
        if (IsBusy) return;

        IsChecking = true;
        ProgressPercent = 0;
        StatusMessage = "Recherche des mises à jour logicielles en cours...";
        _operationCts = new CancellationTokenSource();

        try
        {
            var progress = new Progress<(string Status, int Percent)>(tuple =>
            {
                StatusMessage = tuple.Status;
                ProgressPercent = tuple.Percent;
            });

            var updates = await _updateService.CheckUpdatesAsync(progress, _operationCts.Token);

            AllUpdates.Clear();
            foreach (var u in updates)
            {
                AllUpdates.Add(u);
            }

            ApplyFilters();
            UpdateKpiProperties();
            await LoadHistoryAsync();

            StatusMessage = $"Vérification terminée : {TotalUpdatesCount} mise(s) à jour disponible(s) ({CriticalSecurityCount} critique(s)).";
            SelectedUpdate = FilteredUpdates.FirstOrDefault(u => u.IsAvailable) ?? FilteredUpdates.FirstOrDefault();
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Vérification annulée.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Erreur lors de la vérification : {ex.Message}";
            AppendConsole($"[ERREUR] {ex.Message}");
        }
        finally
        {
            IsChecking = false;
        }
    }

    public void RequestUpgradeSelected()
    {
        if (SelectedUpdate == null || !SelectedUpdate.IsAvailable) return;

        ConfirmationTitle = "Confirmation de Mise à Jour Sécurisée";
        ConfirmationMessage = $"Voulez-vous procéder à l'installation de la mise à jour pour l'application :\r\n\r\n" +
                              $"• Application : {SelectedUpdate.ApplicationName}\r\n" +
                              $"• Identifiant : {SelectedUpdate.PackageIdentifier}\r\n" +
                              $"• Version actuelle : {SelectedUpdate.CurrentVersion}\r\n" +
                              $"• Version cible : {SelectedUpdate.AvailableVersion}\r\n\r\n" +
                              (SelectedUpdate.HasCriticalSecurityPatch ? "⚠️ Cette mise à jour corrige des vulnérabilités critiques signalées par le moteur CVE.\r\n\r\n" : "") +
                              "L'exécution sera effectuée sous supervision sécurisée via WinGet.";

        _pendingConfirmedAction = async () =>
        {
            await ExecuteUpgradeSingleAsync(SelectedUpdate);
        };

        IsConfirmationOpen = true;
    }

    public void RequestUpgradeAll()
    {
        int count = TotalUpdatesCount;
        if (count == 0) return;

        ConfirmationTitle = "Attention : Mise à Jour Globale du Système";
        ConfirmationMessage = $"Vous êtes sur le point de lancer la mise à jour globale de {count} application(s) installée(s).\r\n\r\n" +
                              "Cette opération peut nécessiter des redémarrages de certains services et prendra plusieurs minutes.\r\n\r\n" +
                              "Confirmez-vous le lancement de la commande supervisée 'winget upgrade --all' ?";

        _pendingConfirmedAction = async () =>
        {
            await ExecuteUpgradeAllAsync();
        };

        IsConfirmationOpen = true;
    }

    private async Task ExecuteConfirmedActionAsync()
    {
        IsConfirmationOpen = false;
        if (_pendingConfirmedAction != null)
        {
            var action = _pendingConfirmedAction;
            _pendingConfirmedAction = null;
            await action();
        }
    }

    private void DismissConfirmation()
    {
        IsConfirmationOpen = false;
        _pendingConfirmedAction = null;
    }

    private async Task ExecuteUpgradeSingleAsync(SoftwareUpdateDto update)
    {
        IsUpgrading = true;
        update.Status = UpdateStatus.Updating;
        update.StatusMessage = "Installation en cours...";
        StatusMessage = $"Mise à jour en cours de {update.ApplicationName}...";
        _operationCts = new CancellationTokenSource();

        AppendConsole($"\r\n=== DÉPLOIEMENT DU PACKAGE : {update.PackageIdentifier} ===");

        var consoleProgress = new Progress<string>(AppendConsole);

        try
        {
            // Appel supervisé avec confirmation validée
            var result = await _updateService.UpgradePackageAsync(
                update.PackageIdentifier, 
                isConfirmed: true, 
                consoleProgress, 
                _operationCts.Token);

            if (result.Success)
            {
                update.Status = UpdateStatus.Updated;
                update.StatusMessage = "Mise à jour installée avec succès !";
                update.IsAvailable = false;
                StatusMessage = $"Succès : {update.ApplicationName} a été mis à jour.";
            }
            else
            {
                update.Status = UpdateStatus.Failed;
                update.StatusMessage = result.Message;
                StatusMessage = $"Échec : {update.ApplicationName}. {result.Message}";
            }
        }
        catch (OperationCanceledException)
        {
            update.Status = UpdateStatus.Failed;
            update.StatusMessage = "Opération annulée.";
            StatusMessage = "Mise à jour interrompue par l'utilisateur.";
        }
        catch (Exception ex)
        {
            update.Status = UpdateStatus.Failed;
            update.StatusMessage = ex.Message;
            StatusMessage = $"Erreur : {ex.Message}";
        }
        finally
        {
            IsUpgrading = false;
            UpdateKpiProperties();
            await LoadHistoryAsync();
        }
    }

    private async Task ExecuteUpgradeAllAsync()
    {
        IsUpgrading = true;
        StatusMessage = "Mise à jour globale en cours d'exécution...";
        _operationCts = new CancellationTokenSource();

        AppendConsole("\r\n=== DÉMARRAGE DE LA MISE À JOUR GLOBALE SYSTÈME ===");

        var consoleProgress = new Progress<string>(AppendConsole);

        try
        {
            var result = await _updateService.UpgradeAllAsync(isConfirmed: true, consoleProgress, _operationCts.Token);
            StatusMessage = result.Message;
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Mise à jour globale interrompue.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Erreur : {ex.Message}";
        }
        finally
        {
            IsUpgrading = false;
            await CheckUpdatesAsync();
        }
    }

    public void CancelOperation()
    {
        _operationCts?.Cancel();
    }

    public void ClearLogs()
    {
        ConsoleOutput = "CyberSentinel AI - Logs réinitialisés.\r\n";
    }

    public async Task LoadHistoryAsync()
    {
        var records = await _updateService.GetHistoryAsync();
        UpdateHistory.Clear();
        foreach (var r in records)
        {
            UpdateHistory.Add(r);
        }
        OnPropertyChanged(nameof(HistoryCount));
    }

    public void ApplyFilters()
    {
        FilteredUpdates.Clear();
        var query = AllUpdates.AsEnumerable();

        if (SelectedFilter == "Sécurité Critique")
        {
            query = query.Where(u => u.HasCriticalSecurityPatch && u.IsAvailable);
        }
        else if (SelectedFilter == "Mises à jour dispo")
        {
            query = query.Where(u => u.IsAvailable);
        }
        else if (SelectedFilter == "À jour")
        {
            query = query.Where(u => !u.IsAvailable || u.Status == UpdateStatus.UpToDate);
        }

        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            string term = SearchText.Trim().ToLowerInvariant();
            query = query.Where(u =>
                u.ApplicationName.ToLowerInvariant().Contains(term) ||
                u.PackageIdentifier.ToLowerInvariant().Contains(term) ||
                u.CurrentVersion.ToLowerInvariant().Contains(term) ||
                u.AvailableVersion.ToLowerInvariant().Contains(term));
        }

        foreach (var u in query)
        {
            FilteredUpdates.Add(u);
        }

        if (SelectedUpdate == null || !FilteredUpdates.Contains(SelectedUpdate))
        {
            SelectedUpdate = FilteredUpdates.FirstOrDefault();
        }
    }

    private void UpdateKpiProperties()
    {
        OnPropertyChanged(nameof(TotalUpdatesCount));
        OnPropertyChanged(nameof(CriticalSecurityCount));
        OnPropertyChanged(nameof(UpToDateCount));
        OnPropertyChanged(nameof(CanUpgradeSelected));
        OnPropertyChanged(nameof(CanUpgradeAll));
    }

    private void AppendConsole(string line)
    {
        ConsoleOutput += line + "\r\n";
    }
}

