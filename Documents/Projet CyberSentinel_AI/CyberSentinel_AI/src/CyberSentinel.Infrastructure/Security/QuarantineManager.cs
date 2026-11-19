using System.Security.Cryptography;
using System.Text.Json;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.Security;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Infrastructure.Security;

public class QuarantineManager : IQuarantineService
{
    private readonly string _vaultPath;
    private static readonly byte[] DefaultCipherKey = { 0x53, 0x65, 0x6E, 0x74, 0x69, 0x6E, 0x65, 0x6C, 0x5F, 0x51, 0x75, 0x61, 0x72, 0x61, 0x6E, 0x74 }; // "Sentinel_Quarant"

    public string VaultDirectoryPath => _vaultPath;

    public QuarantineManager(string? customVaultPath = null)
    {
        _vaultPath = customVaultPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), 
            @"CyberSentinel\Quarantine");

        if (!Directory.Exists(_vaultPath))
        {
            Directory.CreateDirectory(_vaultPath);
        }
    }

    public async Task<QuarantineRecord> IsolateFileAsync(string sourceFilePath, string detectionReason, CancellationToken cancellationToken = default)
    {
        // 0. Validation de sécurité du chemin source
        if (!PathSecurityValidator.IsPathSafe(sourceFilePath, out string? sanitizedSource, out string? secErr))
        {
            throw new ArgumentException($"Chemin source non sécurisé : {secErr}", nameof(sourceFilePath));
        }

        sourceFilePath = sanitizedSource!;

        if (!File.Exists(sourceFilePath))
        {
            throw new FileNotFoundException($"Le fichier source à isoler n'existe pas : {sourceFilePath}");
        }

        var sourceFileInfo = new FileInfo(sourceFilePath);
        long fileSize = sourceFileInfo.Length;
        string fileName = sourceFileInfo.Name;

        // 1. Calcul de l'empreinte initiale SHA-256
        string originalSha256;
        using (var sha = SHA256.Create())
        await using (var srcStream = File.OpenRead(sourceFilePath))
        {
            byte[] hash = await sha.ComputeHashAsync(srcStream, cancellationToken);
            originalSha256 = Convert.ToHexString(hash).ToLowerInvariant();
        }

        // 2. Chiffrement et déplacement dans le coffre-fort
        var quarantineId = Guid.NewGuid();
        string lockedFileName = $"{quarantineId}.locked";
        string lockedFilePath = Path.Combine(_vaultPath, lockedFileName);

        await TransformFileAsync(sourceFilePath, lockedFilePath, DefaultCipherKey, cancellationToken);

        // 3. Vérification d'intégrité après chiffrement (en mémoire)
        using (var verifyStream = new MemoryStream())
        {
            await using (var lockedStream = File.OpenRead(lockedFilePath))
            {
                ApplyXorCipher(lockedStream, verifyStream, DefaultCipherKey);
            }
            verifyStream.Position = 0;
            using var sha = SHA256.Create();
            byte[] verifyHash = await sha.ComputeHashAsync(verifyStream, cancellationToken);
            string restoredSha256 = Convert.ToHexString(verifyHash).ToLowerInvariant();

            if (!string.Equals(originalSha256, restoredSha256, StringComparison.OrdinalIgnoreCase))
            {
                // Erreur d'intégrité : supprimer le fichier corrompu et avorter
                if (File.Exists(lockedFilePath)) File.Delete(lockedFilePath);
                throw new InvalidOperationException("Échec du contrôle d'intégrité cryptographique lors de la mise en quarantaine.");
            }
        }

        // 4. Suppression sécurisée du fichier source initial
        File.Delete(sourceFilePath);

        // 5. Sauvegarde des métadonnées
        var record = new QuarantineRecord
        {
            Id = quarantineId,
            OriginalFilePath = sourceFilePath,
            OriginalFileName = fileName,
            QuarantinedFileName = lockedFileName,
            QuarantinedFilePath = lockedFilePath,
            Sha256Hash = originalSha256,
            FileSizeBytes = fileSize,
            DetectionReason = detectionReason,
            EncryptionKeyId = "XOR-V1",
            Status = QuarantineStatus.Isolated,
            QuarantinedAt = DateTime.UtcNow
        };

        string metaPath = Path.Combine(_vaultPath, $"{quarantineId}.meta.json");
        string json = JsonSerializer.Serialize(record, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(metaPath, json, cancellationToken);

        return record;
    }

    public async Task<bool> RestoreFileAsync(Guid quarantineId, CancellationToken cancellationToken = default)
    {
        string metaPath = Path.Combine(_vaultPath, $"{quarantineId}.meta.json");
        string lockedPath = Path.Combine(_vaultPath, $"{quarantineId}.locked");

        if (!File.Exists(metaPath) || !File.Exists(lockedPath))
        {
            return false;
        }

        string json = await File.ReadAllTextAsync(metaPath, cancellationToken);
        var record = JsonSerializer.Deserialize<QuarantineRecord>(json);
        if (record == null)
        {
            return false;
        }

        // Validation stricte du chemin de destination pour bloquer le Path Traversal et les périphériques DOS
        if (!PathSecurityValidator.IsPathSafe(record.OriginalFilePath, out string? sanitizedTarget, out string? pathError))
        {
            throw new InvalidOperationException($"Chemin de restauration corrompu ou illicite dans les métadonnées : {pathError}");
        }

        if (PathSecurityValidator.IsRestrictedSystemPath(sanitizedTarget))
        {
            throw new InvalidOperationException("Restauration interdite vers un répertoire système Windows critique.");
        }

        string safeTargetPath = sanitizedTarget!;
        string targetDir = Path.GetDirectoryName(safeTargetPath) ?? _vaultPath;
        if (!Directory.Exists(targetDir))
        {
            Directory.CreateDirectory(targetDir);
        }

        // 1. Déchiffrement d'abord dans un fichier temporaire isolé de staging (Restauration atomique sécurisée)
        string stagingTempPath = Path.Combine(_vaultPath, $"{quarantineId}.restoring.tmp");
        try
        {
            await TransformFileAsync(lockedPath, stagingTempPath, DefaultCipherKey, cancellationToken);

            // 2. Vérification d'intégrité cryptographique SHA-256 AVANT tout déploiement sur la cible
            using (var sha = SHA256.Create())
            await using (var stagingStream = File.OpenRead(stagingTempPath))
            {
                byte[] hash = await sha.ComputeHashAsync(stagingStream, cancellationToken);
                string stagedSha256 = Convert.ToHexString(hash).ToLowerInvariant();

                if (!string.Equals(record.Sha256Hash, stagedSha256, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("Le hash du fichier restauré ne correspond pas à l'empreinte d'origine (altération ou corruption détectée).");
                }
            }

            // 3. Déploiement atomique vers la destination finale sécurisée
            File.Move(stagingTempPath, safeTargetPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(stagingTempPath))
            {
                try { File.Delete(stagingTempPath); } catch { }
            }
        }

        // 4. Suppression du fichier dans le coffre et mise à jour des métadonnées
        File.Delete(lockedPath);
        record.Status = QuarantineStatus.Restored;
        record.RestoredAt = DateTime.UtcNow;

        string updatedJson = JsonSerializer.Serialize(record, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(metaPath, updatedJson, cancellationToken);

        return true;
    }

    public async Task<bool> PurgeFileAsync(Guid quarantineId, CancellationToken cancellationToken = default)
    {
        string metaPath = Path.Combine(_vaultPath, $"{quarantineId}.meta.json");
        string lockedPath = Path.Combine(_vaultPath, $"{quarantineId}.locked");

        if (!File.Exists(lockedPath))
        {
            return false;
        }

        // Écrasement sécurisé par des zéros avant suppression
        try
        {
            long length = new FileInfo(lockedPath).Length;
            await using (var fs = new FileStream(lockedPath, FileMode.Open, FileAccess.Write))
            {
                byte[] zeros = new byte[Math.Min(length, 64 * 1024)];
                long remaining = length;
                while (remaining > 0)
                {
                    int toWrite = (int)Math.Min(remaining, zeros.Length);
                    await fs.WriteAsync(zeros.AsMemory(0, toWrite), cancellationToken);
                    remaining -= toWrite;
                }
            }
            File.Delete(lockedPath);
        }
        catch
        {
            File.Delete(lockedPath);
        }

        // Mise à jour métadonnées
        if (File.Exists(metaPath))
        {
            string json = await File.ReadAllTextAsync(metaPath, cancellationToken);
            var record = JsonSerializer.Deserialize<QuarantineRecord>(json);
            if (record != null)
            {
                record.Status = QuarantineStatus.Purged;
                string updatedJson = JsonSerializer.Serialize(record, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(metaPath, updatedJson, cancellationToken);
            }
        }

        return true;
    }

    public async Task<IReadOnlyList<QuarantineRecord>> GetAllQuarantinedItemsAsync(CancellationToken cancellationToken = default)
    {
        var records = new List<QuarantineRecord>();
        if (!Directory.Exists(_vaultPath))
        {
            return records;
        }

        var metaFiles = Directory.EnumerateFiles(_vaultPath, "*.meta.json");
        foreach (var file in metaFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                string json = await File.ReadAllTextAsync(file, cancellationToken);
                var record = JsonSerializer.Deserialize<QuarantineRecord>(json);
                if (record != null && record.Status == QuarantineStatus.Isolated)
                {
                    records.Add(record);
                }
            }
            catch
            {
                // Ignorer fichier corrompu
            }
        }

        return records.OrderByDescending(r => r.QuarantinedAt).ToList();
    }

    private static async Task TransformFileAsync(string inputPath, string outputPath, byte[] key, CancellationToken cancellationToken)
    {
        await using var inStream = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, useAsync: true);
        await using var outStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 64 * 1024, useAsync: true);

        byte[] buffer = new byte[64 * 1024];
        long keyOffset = 0;
        int read;

        while ((read = await inStream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)) > 0)
        {
            for (int i = 0; i < read; i++)
            {
                buffer[i] ^= key[(keyOffset + i) % key.Length];
            }
            keyOffset += read;
            await outStream.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
    }

    private static void ApplyXorCipher(Stream input, Stream output, byte[] key)
    {
        byte[] buffer = new byte[64 * 1024];
        long keyOffset = 0;
        int read;

        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            for (int i = 0; i < read; i++)
            {
                buffer[i] ^= key[(keyOffset + i) % key.Length];
            }
            keyOffset += read;
            output.Write(buffer, 0, read);
        }
    }
}

