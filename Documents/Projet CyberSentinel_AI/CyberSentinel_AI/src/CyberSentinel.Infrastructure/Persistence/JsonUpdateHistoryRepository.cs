using System.Text.Json;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Domain.Entities;

namespace CyberSentinel.Infrastructure.Persistence;

public class JsonUpdateHistoryRepository : IUpdateHistoryRepository
{
    private readonly string _filePath;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public JsonUpdateHistoryRepository(string? customDir = null)
    {
        string dir = customDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
            @"CyberSentinel\History");

        if (!Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        _filePath = Path.Combine(dir, "update_history.json");
    }

    public async Task SaveHistoryEntryAsync(UpdateHistoryRecord record, CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var entries = await LoadEntriesInternalAsync(cancellationToken);
            entries.Insert(0, record); // Plus récent en premier

            // Conserver au maximum 500 entrées d'historique
            if (entries.Count > 500)
            {
                entries = entries.Take(500).ToList();
            }

            string json = JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(_filePath, json, cancellationToken);
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<IReadOnlyList<UpdateHistoryRecord>> GetAllHistoryAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            return await LoadEntriesInternalAsync(cancellationToken);
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<List<UpdateHistoryRecord>> LoadEntriesInternalAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_filePath))
        {
            return new List<UpdateHistoryRecord>();
        }

        try
        {
            string json = await File.ReadAllTextAsync(_filePath, cancellationToken);
            return JsonSerializer.Deserialize<List<UpdateHistoryRecord>>(json) ?? new List<UpdateHistoryRecord>();
        }
        catch
        {
            return new List<UpdateHistoryRecord>();
        }
    }
}

