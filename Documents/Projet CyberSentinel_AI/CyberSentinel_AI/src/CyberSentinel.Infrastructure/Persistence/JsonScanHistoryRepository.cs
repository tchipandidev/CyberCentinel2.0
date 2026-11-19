using System.Text.Json;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Domain.Entities;

namespace CyberSentinel.Infrastructure.Persistence;

public class JsonScanHistoryRepository : IScanHistoryRepository
{
    private readonly string _storageFile;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public JsonScanHistoryRepository(string? customHistoryDir = null)
    {
        string dir = customHistoryDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
            @"CyberSentinel\History");

        if (!Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        _storageFile = Path.Combine(dir, "sessions.json");
    }

    public async Task SaveSessionAsync(ScanSession session, CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var sessions = (await LoadSessionsInternalAsync(cancellationToken)).ToList();
            int existingIndex = sessions.FindIndex(s => s.Id == session.Id);
            if (existingIndex >= 0)
            {
                sessions[existingIndex] = session;
            }
            else
            {
                sessions.Insert(0, session);
            }

            // Conserver les 100 dernières sessions
            var trimmed = sessions.Take(100).ToList();
            string json = JsonSerializer.Serialize(trimmed, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(_storageFile, json, cancellationToken);
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<IReadOnlyList<ScanSession>> GetRecentSessionsAsync(int maxCount = 20, CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var sessions = await LoadSessionsInternalAsync(cancellationToken);
            return sessions.OrderByDescending(s => s.StartedAt).Take(maxCount).ToList();
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<ScanSession?> GetSessionByIdAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var sessions = await LoadSessionsInternalAsync(cancellationToken);
            return sessions.FirstOrDefault(s => s.Id == sessionId);
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<IEnumerable<ScanSession>> LoadSessionsInternalAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_storageFile))
        {
            return Enumerable.Empty<ScanSession>();
        }

        try
        {
            string json = await File.ReadAllTextAsync(_storageFile, cancellationToken);
            var sessions = JsonSerializer.Deserialize<List<ScanSession>>(json);
            return sessions ?? Enumerable.Empty<ScanSession>();
        }
        catch
        {
            return Enumerable.Empty<ScanSession>();
        }
    }
}

