using System.Diagnostics;
using System.Text.RegularExpressions;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.Security;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Infrastructure.Security;

public class ClamAvScanner : IAntivirusScanner
{
    private readonly string _executablePath;
    private readonly TimeSpan _executionTimeout;
    private static readonly Regex FoundPattern = new(@"^.+:\s*(.+?)\s+FOUND$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex OkPattern = new(@"^.+:\s*OK$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public string EngineName => "ClamAV Antivirus";

    public ClamAvScanner(string? customExecutablePath = null, TimeSpan? timeout = null)
    {
        _executablePath = ResolveClamExecutable(customExecutablePath);
        _executionTimeout = timeout ?? TimeSpan.FromSeconds(45);
    }

    public Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        bool exists = !string.IsNullOrEmpty(_executablePath) && File.Exists(_executablePath);
        return Task.FromResult(exists);
    }

    public async Task<EngineScanResult> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();

        if (!PathSecurityValidator.IsPathSafe(filePath, out string? sanitizedPath, out string? securityError))
        {
            return EngineScanResult.Failure(EngineType.ClamAV, $"Chemin non sécurisé rejeté : {securityError}");
        }

        filePath = sanitizedPath!;

        if (!File.Exists(filePath))
        {
            return EngineScanResult.Failure(EngineType.ClamAV, $"Fichier introuvable : {filePath}");
        }

        if (!await IsAvailableAsync(cancellationToken))
        {
            return EngineScanResult.Success(
                EngineType.ClamAV,
                ThreatVerdict.Unsupported,
                RiskLevel.None,
                null,
                "Moteur ClamAV non installé ou introuvable sur le système hôte.",
                0);
        }

        try
        {
            using var timeoutCts = new CancellationTokenSource(_executionTimeout);
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

            var startInfo = new ProcessStartInfo
            {
                FileName = _executablePath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            // ArgumentList évite toute injection de commande
            startInfo.ArgumentList.Add("--no-summary");
            startInfo.ArgumentList.Add("--infected");
            startInfo.ArgumentList.Add(filePath);

            using var process = new Process { StartInfo = startInfo };
            process.Start();

            var stdoutTask = process.StandardOutput.ReadToEndAsync(linkedCts.Token);
            var stderrTask = process.StandardError.ReadToEndAsync(linkedCts.Token);

            try
            {
                await process.WaitForExitAsync(linkedCts.Token);
            }
            catch (OperationCanceledException)
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                    }
                }
                catch { }

                if (timeoutCts.IsCancellationRequested)
                {
                    return EngineScanResult.Failure(
                        EngineType.ClamAV, 
                        $"Délai d'exécution dépassé ({_executionTimeout.TotalSeconds}s) lors de l'analyse ClamAV.", 
                        stopwatch.ElapsedMilliseconds);
                }
                throw;
            }

            string stdout = await stdoutTask;
            string stderr = await stderrTask;
            stopwatch.Stop();

            return ParseOutput(stdout, stderr, process.ExitCode, stopwatch.ElapsedMilliseconds);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            return EngineScanResult.Failure(
                EngineType.ClamAV, 
                $"Erreur d'exécution ClamAV : {ex.Message}", 
                stopwatch.ElapsedMilliseconds);
        }
    }

    public static EngineScanResult ParseOutput(string stdout, string stderr, int exitCode, long durationMs)
    {
        // Code retour ClamAV standard :
        // 0 = Aucun virus trouvé (OK)
        // 1 = Virus trouvé (Infected)
        // 2 = Erreur rencontrée

        var lines = (stdout ?? string.Empty)
            .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim())
            .ToList();

        foreach (var line in lines)
        {
            var match = FoundPattern.Match(line);
            if (match.Success)
            {
                string virusName = match.Groups[1].Value.Trim();
                return EngineScanResult.Success(
                    EngineType.ClamAV,
                    ThreatVerdict.Malicious,
                    RiskLevel.Critical,
                    virusName,
                    $"Signature virale détectée par ClamAV : {virusName}",
                    durationMs);
            }

            if (OkPattern.IsMatch(line))
            {
                return EngineScanResult.Success(
                    EngineType.ClamAV,
                    ThreatVerdict.Clean,
                    RiskLevel.None,
                    null,
                    "Aucune signature virale détectée.",
                    durationMs);
            }
        }

        if (exitCode == 1)
        {
            return EngineScanResult.Success(
                EngineType.ClamAV,
                ThreatVerdict.Malicious,
                RiskLevel.Critical,
                "Threat.Generic.Found",
                "Menace détectée (code de sortie 1)",
                durationMs);
        }

        if (exitCode == 0)
        {
            return EngineScanResult.Success(
                EngineType.ClamAV,
                ThreatVerdict.Clean,
                RiskLevel.None,
                null,
                "Fichier sain (code de sortie 0)",
                durationMs);
        }

        string errorDetails = !string.IsNullOrWhiteSpace(stderr) ? stderr : (stdout ?? "Détails indisponibles");
        return EngineScanResult.Failure(
            EngineType.ClamAV, 
            $"Erreur ClamAV (Code {exitCode}) : {errorDetails.Trim()}", 
            durationMs);
    }

    private static string ResolveClamExecutable(string? customPath)
    {
        if (!string.IsNullOrEmpty(customPath) && File.Exists(customPath))
        {
            return customPath;
        }

        string? localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string[] candidates = {
            @"C:\Program Files\ClamAV\clamdscan.exe",
            @"C:\Program Files\ClamAV\clamscan.exe",
            @"C:\Program Files (x86)\ClamAV\clamdscan.exe",
            @"C:\Program Files (x86)\ClamAV\clamscan.exe",
            !string.IsNullOrEmpty(localAppData) ? Path.Combine(localAppData, @"CyberSentinel\ClamAV\clamscan.exe") : string.Empty
        };

        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return string.Empty;
    }
}
