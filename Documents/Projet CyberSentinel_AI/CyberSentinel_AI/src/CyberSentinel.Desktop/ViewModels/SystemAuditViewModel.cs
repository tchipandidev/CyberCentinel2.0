using System.Collections.ObjectModel;
using System.Text;
using System.Windows;
using System.Windows.Input;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.DTOs;
using CyberSentinel.Desktop.Common;
using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Desktop.ViewModels;

public class SystemAuditViewModel : ViewModelBase
{
    private readonly ISystemAuditOrchestrator _auditOrchestrator;
    private readonly IUpdateManager _updateManager;
    private CancellationTokenSource? _auditCts;

    private bool _isAuditing;
    private bool _isUpdating;
    private string _currentStep = "Prêt à lancer l'audit de sécurité du système.";
    private int _progressPercent;
    private int _totalApplicationsCount;
    private int _vulnerableApplicationsCount;
    private int _availableUpdatesCount;
    private int _criticalVulnerabilitiesCount;
    private string _securityPostureScore = "A (Optimal)";
    private string _consoleOutput = "CyberSentinel AI - Module de Remédiation & WinGet initialisé.\r\n";
    private InstalledApplicationDto? _selectedApplication;
    private SoftwareUpdateDto? _selectedUpdate;

    public ObservableCollection<InstalledApplicationDto> InstalledApplications { get; } = new();
    public ObservableCollection<SoftwareUpdateDto> AvailableUpdates { get; } = new();
    public ObservableCollection<VulnerabilityDto> AllVulnerabilities { get; } = new();

    public bool IsAuditing
    {
        get => _isAuditing;
        set
        {
            if (SetProperty(ref _isAuditing, value))
            {
                OnPropertyChanged(nameof(CanStartAudit));
                OnPropertyChanged(nameof(CanCancelAudit));
            }
        }
    }

    public bool IsUpdating
    {
        get => _isUpdating;
        set
        {
            if (SetProperty(ref _isUpdating, value))
            {
                OnPropertyChanged(nameof(CanApplyUpdates));
            }
        }
    }

    public bool CanStartAudit => !IsAuditing && !IsUpdating;
    public bool CanCancelAudit => IsAuditing;
    public bool CanApplyUpdates => !IsUpdating && !IsAuditing && AvailableUpdates.Count > 0;

    public string CurrentStep
    {
        get => _currentStep;
        set => SetProperty(ref _currentStep, value);
    }

    public int ProgressPercent
    {
        get => _progressPercent;
        set => SetProperty(ref _progressPercent, value);
    }

    public int TotalApplicationsCount
    {
        get => _totalApplicationsCount;
        set => SetProperty(ref _totalApplicationsCount, value);
    }

    public int VulnerableApplicationsCount
    {
        get => _vulnerableApplicationsCount;
        set => SetProperty(ref _vulnerableApplicationsCount, value);
    }

    public int AvailableUpdatesCount
    {
        get => _availableUpdatesCount;
        set => SetProperty(ref _availableUpdatesCount, value);
    }

    public int CriticalVulnerabilitiesCount
    {
        get => _criticalVulnerabilitiesCount;
        set => SetProperty(ref _criticalVulnerabilitiesCount, value);
    }

    public string SecurityPostureScore
    {
        get => _securityPostureScore;
        set => SetProperty(ref _securityPostureScore, value);
    }

    public string ConsoleOutput
    {
        get => _consoleOutput;
        set => SetProperty(ref _consoleOutput, value);
    }

    public InstalledApplicationDto? SelectedApplication
    {
        get => _selectedApplication;
        set => SetProperty(ref _selectedApplication, value);
    }

    public SoftwareUpdateDto? SelectedUpdate
    {
        get => _selectedUpdate;
        set => SetProperty(ref _selectedUpdate, value);
    }

    public ICommand RunAuditCommand { get; }
    public ICommand CancelAuditCommand { get; }
    public ICommand ApplyUpdateCommand { get; }
    public ICommand ApplyAllUpdatesCommand { get; }
    public ICommand ClearConsoleCommand { get; }

    public SystemAuditViewModel(
        ISystemAuditOrchestrator auditOrchestrator,
        IUpdateManager updateManager)
    {
        _auditOrchestrator = auditOrchestrator ?? throw new ArgumentNullException(nameof(auditOrchestrator));
        _updateManager = updateManager ?? throw new ArgumentNullException(nameof(updateManager));

        RunAuditCommand = new AsyncRelayCommand(RunAuditAsync, () => CanStartAudit);
        CancelAuditCommand = new RelayCommand(CancelAudit, () => CanCancelAudit);
        ApplyUpdateCommand = new AsyncRelayCommand<SoftwareUpdateDto>(ApplySingleUpdateAsync, u => CanApplyUpdates && (u != null || SelectedUpdate != null));
        ApplyAllUpdatesCommand = new AsyncRelayCommand(ApplyAllUpdatesAsync, () => CanApplyUpdates);
        ClearConsoleCommand = new RelayCommand(() => ConsoleOutput = string.Empty);
    }

    public async Task RunAuditAsync()
    {
        if (IsAuditing) return;

        IsAuditing = true;
        ProgressPercent = 0;
        CurrentStep = "Initialisation de l'audit système...";
        _auditCts = new CancellationTokenSource();

        try
        {
            var progressHandler = new Progress<(string Step, int Percent)>(report =>
            {
                System.Windows.Application.Current?.Dispatcher.Invoke(() =>
                {
                    CurrentStep = report.Step;
                    ProgressPercent = report.Percent;
                });
            });

            var (apps, summary) = await _auditOrchestrator.RunSystemAuditAsync(progressHandler, _auditCts.Token);

            InstalledApplications.Clear();
            AvailableUpdates.Clear();
            AllVulnerabilities.Clear();

            foreach (var app in apps)
            {
                InstalledApplications.Add(app);

                if (app.AvailableUpdate != null)
                {
                    AvailableUpdates.Add(app.AvailableUpdate);
                }

                foreach (var v in app.Vulnerabilities)
                {
                    AllVulnerabilities.Add(v);
                }
            }

            TotalApplicationsCount = summary.TotalInstalledSoftware;
            VulnerableApplicationsCount = summary.VulnerableSoftwareCount;
            AvailableUpdatesCount = summary.UpdatesAvailableCount;
            CriticalVulnerabilitiesCount = summary.CriticalCvesCount;
            SecurityPostureScore = $"{summary.PostureVerdict} ({summary.GlobalExposureScore:F0}/100)";

            CurrentStep = $"Audit terminé : {summary.TotalInstalledSoftware} applications, {summary.TotalCvesFound} vulnérabilité(s).";
            AppendConsole($"[{DateTime.Now:HH:mm:ss}] Audit système terminé : Posture = {summary.PostureVerdict} (Score = {summary.GlobalExposureScore:F0}/100).");
        }
        catch (OperationCanceledException)
        {
            CurrentStep = "Audit système interrompu par l'utilisateur.";
            AppendConsole($"[{DateTime.Now:HH:mm:ss}] Audit interrompu.");
        }
        catch (Exception ex)
        {
            CurrentStep = $"Erreur d'audit : {ex.Message}";
            AppendConsole($"[{DateTime.Now:HH:mm:ss}] ERREUR AUDIT : {ex.Message}");
            MessageBox.Show($"Une erreur est survenue durant l'audit système :\r\n{ex.Message}", "Erreur Système", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsAuditing = false;
            _auditCts?.Dispose();
            _auditCts = null;
        }
    }

    public void CancelAudit()
    {
        if (_auditCts != null && !_auditCts.IsCancellationRequested)
        {
            CurrentStep = "Interruption en cours...";
            _auditCts.Cancel();
        }
    }

    public async Task ApplySingleUpdateAsync(SoftwareUpdateDto? target)
    {
        var update = target ?? SelectedUpdate;
        if (update == null || IsUpdating) return;

        IsUpdating = true;
        update.Status = UpdateStatus.Updating;
        AppendConsole($"[{DateTime.Now:HH:mm:ss}] Démarrage de la mise à jour pour '{update.ApplicationName}' (ID: {update.PackageIdentifier})...");

        try
        {
            var consoleReporter = new Progress<string>(line =>
            {
                System.Windows.Application.Current?.Dispatcher.Invoke(() => AppendConsole(line));
            });

            var result = await _updateManager.ApplyUpdateAsync(update.PackageIdentifier, consoleReporter);

            if (result.Success)
            {
                update.Status = UpdateStatus.Updated;
                AppendConsole($"[{DateTime.Now:HH:mm:ss}] [SUCCÈS] '{update.ApplicationName}' a été mis à niveau avec succès.");
                AvailableUpdates.Remove(update);
                AvailableUpdatesCount = AvailableUpdates.Count;
            }
            else
            {
                update.Status = UpdateStatus.Failed;
                AppendConsole($"[{DateTime.Now:HH:mm:ss}] [ÉCHEC] Erreur lors de la mise à niveau : {result.ErrorMessage} (Code de sortie: {result.ExitCode})");
            }
        }
        catch (Exception ex)
        {
            update.Status = UpdateStatus.Failed;
            AppendConsole($"[{DateTime.Now:HH:mm:ss}] [EXCEPTION] {ex.Message}");
        }
        finally
        {
            IsUpdating = false;
        }
    }

    public async Task ApplyAllUpdatesAsync()
    {
        if (IsUpdating || AvailableUpdates.Count == 0) return;

        var confirm = MessageBox.Show(
            $"Êtes-vous sûr de vouloir installer les {AvailableUpdates.Count} mises à jour disponibles de façon supervisée ?",
            "Confirmation de Remédiation",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (confirm != MessageBoxResult.Yes) return;

        var updatesToApply = AvailableUpdates.ToList();
        AppendConsole($"[{DateTime.Now:HH:mm:ss}] Lancement du déploiement groupé de {updatesToApply.Count} paquet(s)...");

        foreach (var update in updatesToApply)
        {
            await ApplySingleUpdateAsync(update);
        }

        AppendConsole($"[{DateTime.Now:HH:mm:ss}] Cycle de remédiation groupé terminé.");
    }

    private void AppendConsole(string text)
    {
        ConsoleOutput += text + "\r\n";
    }
}
