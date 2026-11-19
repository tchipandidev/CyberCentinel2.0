using System.Text.Json;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Domain.Entities;

namespace CyberSentinel.Infrastructure.Persistence;

public class SqliteInventoryRepository : IInventoryRepository
{
    private readonly string _storageDir;
    private readonly string _jsonFilePath;
    private readonly string _sqlDumpPath;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public SqliteInventoryRepository(string? customDir = null)
    {
        _storageDir = customDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            @"CyberSentinel\Database");

        if (!Directory.Exists(_storageDir))
        {
            Directory.CreateDirectory(_storageDir);
        }

        _jsonFilePath = Path.Combine(_storageDir, "inventory_history.json");
        _sqlDumpPath = Path.Combine(_storageDir, "inventory_records.sql");
    }

    public async Task SaveInventorySessionAsync(InventorySession session, CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var history = await LoadHistoryInternalAsync(cancellationToken);
            history.RemoveAll(s => s.Id == session.Id);
            history.Insert(0, session);

            // 1. Sauvegarde du journal d'instantanés (Snapshots)
            var options = new JsonSerializerOptions { WriteIndented = true };
            string json = JsonSerializer.Serialize(history, options);
            await File.WriteAllTextAsync(_jsonFilePath, json, cancellationToken);

            // 2. Génération du dump DDL / DML SQLite standard (Merise MLD/MPD)
            await AppendSqliteDumpAsync(session, cancellationToken);
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<IReadOnlyList<InventorySession>> GetInventoryHistoryAsync(int maxCount = 20, CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var history = await LoadHistoryInternalAsync(cancellationToken);
            return history.Take(maxCount).ToList();
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<InventorySession?> GetInventorySessionByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var history = await LoadHistoryInternalAsync(cancellationToken);
            return history.FirstOrDefault(s => s.Id == id);
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<List<InventorySession>> LoadHistoryInternalAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_jsonFilePath))
        {
            return new List<InventorySession>();
        }

        try
        {
            string json = await File.ReadAllTextAsync(_jsonFilePath, cancellationToken);
            var items = JsonSerializer.Deserialize<List<InventorySession>>(json);
            return items ?? new List<InventorySession>();
        }
        catch
        {
            return new List<InventorySession>();
        }
    }

    private async Task AppendSqliteDumpAsync(InventorySession session, CancellationToken cancellationToken)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"-- Snapshot ID: {session.Id} à {session.SnapshotDate:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"INSERT OR REPLACE INTO InventorySessions (Id, SnapshotDate, TotalApplicationsCount, X64ApplicationsCount, X86ApplicationsCount, MachineName, OsVersion) VALUES ('{session.Id}', '{session.SnapshotDate:O}', {session.TotalApplicationsCount}, {session.X64ApplicationsCount}, {session.X86ApplicationsCount}, '{EscapeSql(session.MachineName)}', '{EscapeSql(session.OsVersion)}');");

        foreach (var app in session.Applications)
        {
            string installDateVal = app.InstallDate.HasValue ? $"'{app.InstallDate.Value:O}'" : "NULL";
            string pkgVal = !string.IsNullOrEmpty(app.PackageIdentifier) ? $"'{EscapeSql(app.PackageIdentifier)}'" : "NULL";

            sb.AppendLine($"INSERT OR REPLACE INTO InstalledSoftware (Id, SessionId, DisplayName, Publisher, DisplayVersion, Architecture, InstallDate, InstallLocation, IdentificationSource, PackageIdentifier) VALUES ('{app.Id}', '{session.Id}', '{EscapeSql(app.DisplayName)}', '{EscapeSql(app.Publisher)}', '{EscapeSql(app.DisplayVersion)}', '{app.Architecture}', {installDateVal}, '{EscapeSql(app.InstallLocation)}', '{EscapeSql(app.IdentificationSource)}', {pkgVal});");
        }

        sb.AppendLine();
        await File.AppendAllTextAsync(_sqlDumpPath, sb.ToString(), cancellationToken);
    }

    public static string EscapeSql(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        // Neutralisation des injections SQL par troncature, null bytes et multi-lignes
        return value
            .Replace("\0", string.Empty)
            .Replace("\r", " ")
            .Replace("\n", " ")
            .Replace("'", "''")
            .Trim();
    }
}

