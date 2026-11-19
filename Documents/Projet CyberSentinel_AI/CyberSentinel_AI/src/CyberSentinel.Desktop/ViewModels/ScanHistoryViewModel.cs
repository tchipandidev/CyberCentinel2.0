using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows.Input;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.DTOs;
using CyberSentinel.Desktop.Common;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Desktop.ViewModels;

public class ScanHistoryViewModel : ViewModelBase
{
    private readonly IScanHistoryRepository _historyRepo;
    private readonly IReportService _reportService;

    private bool _isLoading;
    private string _statusMessage = "Prêt à consulter l'historique des analyses.";
    private string _searchText = string.Empty;
    private string _selectedVerdictFilter = "Tous";
    private ScanSessionSummaryDto? _selectedSession;
    private ScanSession? _loadedFullSession;

    public ObservableCollection<ScanSessionSummaryDto> AllSessions { get; } = new();
    public ObservableCollection<ScanSessionSummaryDto> FilteredSessions { get; } = new();
    public ObservableCollection<ScannedFileDto> SelectedSessionFiles { get; } = new();

    public IReadOnlyList<string> VerdictFilters { get; } = new[]
    {
        "Tous", "Menaces Détectées", "Suspects Uniquement", "Sains"
    };

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

    public string SelectedVerdictFilter
    {
        get => _selectedVerdictFilter;
        set
        {
            if (SetProperty(ref _selectedVerdictFilter, value))
            {
                ApplyFilters();
            }
        }
    }

    public ScanSessionSummaryDto? SelectedSession
    {
        get => _selectedSession;
        set
        {
            if (SetProperty(ref _selectedSession, value))
            {
                OnPropertyChanged(nameof(HasSelectedSession));
                _ = LoadSessionDetailsAsync(value);
            }
        }
    }

    public bool HasSelectedSession => SelectedSession != null;
    public int TotalSessionsCount => AllSessions.Count;

    // Commandes
    public ICommand RefreshCommand { get; }
    public ICommand ClearFiltersCommand { get; }
    public ICommand ExportSessionPdfCommand { get; }
    public ICommand ExportSessionJsonCommand { get; }

    public ScanHistoryViewModel(IScanHistoryRepository historyRepo, IReportService reportService)
    {
        _historyRepo = historyRepo ?? throw new ArgumentNullException(nameof(historyRepo));
        _reportService = reportService ?? throw new ArgumentNullException(nameof(reportService));

        RefreshCommand = new RelayCommand(async () => await LoadHistoryAsync());
        ClearFiltersCommand = new RelayCommand(ClearFilters);
        ExportSessionPdfCommand = new RelayCommand(async () => await ExportSessionPdfAsync(), () => HasSelectedSession);
        ExportSessionJsonCommand = new RelayCommand(async () => await ExportSessionJsonAsync(), () => HasSelectedSession);

        _ = LoadHistoryAsync();
    }

    public async Task LoadHistoryAsync()
    {
        IsLoading = true;
        StatusMessage = "Chargement des sessions d'analyse...";

        try
        {
            var sessions = await _historyRepo.GetRecentSessionsAsync(100);
            AllSessions.Clear();

            foreach (var s in sessions)
            {
                AllSessions.Add(new ScanSessionSummaryDto
                {
                    SessionId = s.Id,
                    StartedAt = s.StartedAt,
                    TargetPath = s.TargetPath,
                    ScanType = s.Type,
                    Status = s.Status,
                    TotalFilesCount = s.ScannedFilesCount,
                    MaliciousFilesCount = s.MaliciousFilesCount,
                    SuspiciousFilesCount = s.SuspiciousFilesCount,
                    CleanFilesCount = s.CleanFilesCount,
                    DurationMs = s.DurationMs
                });
            }

            ApplyFilters();
            OnPropertyChanged(nameof(TotalSessionsCount));
            StatusMessage = $"{AllSessions.Count} session(s) d'analyse chargée(s).";

            if (SelectedSession == null && FilteredSessions.Count > 0)
            {
                SelectedSession = FilteredSessions[0];
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Erreur : {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    public void ApplyFilters()
    {
        FilteredSessions.Clear();
        var query = AllSessions.AsEnumerable();

        if (SelectedVerdictFilter == "Menaces Détectées")
        {
            query = query.Where(s => s.MaliciousFilesCount > 0);
        }
        else if (SelectedVerdictFilter == "Suspects Uniquement")
        {
            query = query.Where(s => s.SuspiciousFilesCount > 0 && s.MaliciousFilesCount == 0);
        }
        else if (SelectedVerdictFilter == "Sains")
        {
            query = query.Where(s => s.MaliciousFilesCount == 0 && s.SuspiciousFilesCount == 0);
        }

        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            string term = SearchText.Trim().ToLowerInvariant();
            query = query.Where(s =>
                s.TargetPath.ToLowerInvariant().Contains(term) ||
                s.SessionId.ToString().ToLowerInvariant().Contains(term) ||
                s.ScanTypeBadge.ToLowerInvariant().Contains(term));
        }

        foreach (var item in query)
        {
            FilteredSessions.Add(item);
        }

        if (SelectedSession == null || !FilteredSessions.Contains(SelectedSession))
        {
            SelectedSession = FilteredSessions.FirstOrDefault();
        }
    }

    public void ClearFilters()
    {
        SearchText = string.Empty;
        SelectedVerdictFilter = "Tous";
    }

    private async Task LoadSessionDetailsAsync(ScanSessionSummaryDto? summary)
    {
        SelectedSessionFiles.Clear();
        if (summary == null) return;

        try
        {
            _loadedFullSession = await _historyRepo.GetSessionByIdAsync(summary.SessionId);
            if (_loadedFullSession != null)
            {
                foreach (var file in _loadedFullSession.Files)
                {
                    string threatSource = file.EngineResults.FirstOrDefault(e => e.Verdict >= ThreatVerdict.Suspicious)?.ThreatName 
                                          ?? "Arbitre Multi-Moteurs";

                    SelectedSessionFiles.Add(new ScannedFileDto
                    {
                        FileName = Path.GetFileName(file.FilePath),
                        FilePath = file.FilePath,
                        Sha256Hash = file.Sha256Hash,
                        Verdict = file.Verdict,
                        DetectionSummary = threatSource,
                        AnalyzedAt = file.AnalyzedAt
                    });
                }
            }
        }
        catch { }
    }

    private async Task ExportSessionPdfAsync()
    {
        if (SelectedSession == null) return;

        StatusMessage = "Génération du rapport PDF de la session...";
        try
        {
            var report = await _reportService.GenerateSessionReportAsync(SelectedSession.SessionId);
            string path = await _reportService.ExportReportToPdfAsync(report);
            StatusMessage = $"Rapport exporté : {path}";

            Process.Start(new ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            StatusMessage = $"Échec de l'export : {ex.Message}";
        }
    }

    private async Task ExportSessionJsonAsync()
    {
        if (SelectedSession == null) return;

        StatusMessage = "Export JSON de la session...";
        try
        {
            var report = await _reportService.GenerateSessionReportAsync(SelectedSession.SessionId);
            string path = await _reportService.ExportReportToJsonAsync(report);
            StatusMessage = $"Rapport JSON exporté : {path}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Échec : {ex.Message}";
        }
    }
}
