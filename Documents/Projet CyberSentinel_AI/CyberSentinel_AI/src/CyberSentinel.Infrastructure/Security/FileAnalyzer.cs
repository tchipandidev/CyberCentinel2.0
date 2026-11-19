using System.Security.Cryptography;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.Security;

namespace CyberSentinel.Infrastructure.Security;

public class FileAnalyzer : IFileAnalyzer
{
    private static readonly byte[] PeSignature = { 0x50, 0x45, 0x00, 0x00 }; // 'PE\0\0'

    public async Task<FileInspectionResult> InspectFileAsync(string filePath, CancellationToken cancellationToken = default)
    {
        // 1. Contrôle de sécurité préventif (Anti-Path Traversal / Anti-DOS Device injection / Anti-ADS)
        if (!PathSecurityValidator.IsPathSafe(filePath, out string? sanitizedPath, out string? securityError))
        {
            return new FileInspectionResult(
                filePath ?? string.Empty,
                Path.GetFileName(filePath ?? string.Empty),
                0,
                string.Empty,
                false,
                false,
                $"Chemin non sécurisé rejeté : {securityError}");
        }

        filePath = sanitizedPath!;

        if (!File.Exists(filePath))
        {
            return new FileInspectionResult(
                filePath, 
                Path.GetFileName(filePath), 
                0, 
                string.Empty, 
                false, 
                false, 
                "Le fichier spécifié n'existe pas.");
        }

        try
        {
            var fileInfo = new FileInfo(filePath);
            long fileSize = fileInfo.Length;
            string fileName = fileInfo.Name;

            string sha256 = await ComputeSha256Async(filePath, cancellationToken);
            bool isPe = CheckIsPortableExecutable(filePath);

            return new FileInspectionResult(
                filePath,
                fileName,
                fileSize,
                sha256,
                isPe,
                true,
                null);
        }
        catch (UnauthorizedAccessException ex)
        {
            return new FileInspectionResult(
                filePath,
                Path.GetFileName(filePath),
                0,
                string.Empty,
                false,
                false,
                $"Accès refusé : {ex.Message}");
        }
        catch (IOException ex)
        {
            return new FileInspectionResult(
                filePath,
                Path.GetFileName(filePath),
                0,
                string.Empty,
                false,
                false,
                $"Fichier verrouillé ou erreur d'E/S : {ex.Message}");
        }
        catch (Exception ex)
        {
            return new FileInspectionResult(
                filePath,
                Path.GetFileName(filePath),
                0,
                string.Empty,
                false,
                false,
                $"Erreur inattendue : {ex.Message}");
        }
    }

    public async Task<string> ComputeSha256Async(string filePath, CancellationToken cancellationToken = default)
    {
        using var sha256 = SHA256.Create();
        await using var stream = new FileStream(
            filePath, 
            FileMode.Open, 
            FileAccess.Read, 
            FileShare.ReadWrite, 
            bufferSize: 64 * 1024, 
            useAsync: true);

        byte[] hashBytes = await sha256.ComputeHashAsync(stream, cancellationToken);
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    public bool IsPeHeader(byte[] headerBytes)
    {
        if (headerBytes == null || headerBytes.Length < 64)
        {
            return false;
        }

        // 'MZ' magic number
        if (headerBytes[0] != 0x4D || headerBytes[1] != 0x5A)
        {
            return false;
        }

        // Offset to PE Header is stored at 0x3C (DWORD)
        int peOffset = BitConverter.ToInt32(headerBytes, 0x3C);
        if (peOffset < 0 || peOffset + 4 > headerBytes.Length)
        {
            return false;
        }

        return headerBytes[peOffset] == PeSignature[0] &&
               headerBytes[peOffset + 1] == PeSignature[1] &&
               headerBytes[peOffset + 2] == PeSignature[2] &&
               headerBytes[peOffset + 3] == PeSignature[3];
    }

    private bool CheckIsPortableExecutable(string filePath)
    {
        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] header = new byte[1024];
            int read = stream.Read(header, 0, header.Length);
            if (read < 64)
            {
                return false;
            }

            // 'MZ' header check
            if (header[0] != 0x4D || header[1] != 0x5A)
            {
                return false;
            }

            int peOffset = BitConverter.ToInt32(header, 0x3C);
            if (peOffset <= 0 || peOffset + 4 > read)
            {
                // If PE offset is further in the file, seek and check
                if (peOffset > 0 && peOffset + 4 <= stream.Length)
                {
                    stream.Seek(peOffset, SeekOrigin.Begin);
                    byte[] peSig = new byte[4];
                    stream.ReadExactly(peSig, 0, 4);
                    return peSig.SequenceEqual(PeSignature);
                }
                return false;
            }

            return header[peOffset] == PeSignature[0] &&
                   header[peOffset + 1] == PeSignature[1] &&
                   header[peOffset + 2] == PeSignature[2] &&
                   header[peOffset + 3] == PeSignature[3];
        }
        catch
        {
            return false;
        }
    }
}

