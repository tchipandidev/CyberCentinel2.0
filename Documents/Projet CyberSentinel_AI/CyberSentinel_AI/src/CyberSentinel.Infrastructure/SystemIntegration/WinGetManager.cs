using System.Diagnostics;
using System.Text.RegularExpressions;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Infrastructure.SystemIntegration;

public class WinGetManager : IUpdateManager
{
    private readonly string _wingetPath;
    private string? _cachedVersion;

    public bool IsWinGetAvailable => CheckWinGetAvailability();

    public WinGetManager(string? customWingetPath = null)
    {
        _wingetPath = customWingetPath ?? ResolveWinGetExecutable();
    }

    public string GetWinGetVersion()
    {
        if (_cachedVersion != null) return _cachedVersion;

        if (string.IsNullOrEmpty(_wingetPath) || !File.Exists(_wingetPath))
        {
            _cachedVersion = "Non détecté";
            return _cachedVersion;
        }

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = _wingetPath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            startInfo.ArgumentList.Add("--version");

            using var process = Process.Start(startInfo);
            if (process != null)
            {
                string output = process.StandardOutput.ReadToEnd().Trim();
                process.WaitForExit(3000);
                if (process.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
                {
                    _cachedVersion = output.Split('\r', '\n').FirstOrDefault()?.Trim() ?? "v1.x";
                    return _cachedVersion;
                }
            }
        }
        catch
        {
            // Erreur d'accès ou droits
        }

        _cachedVersion = "v1.x (Standard)";
        return _cachedVersion;
    }

    public async Task<IReadOnlyDictionary<string, SoftwareUpdateInfo>> DiscoverAvailableUpdatesAsync(
        IEnumerable<InstalledApplication> applications, 
        CancellationToken cancellationToken = default)
    {
        var updates = new Dictionary<string, SoftwareUpdateInfo>(StringComparer.OrdinalIgnoreCase);

        if (!IsWinGetAvailable)
        {
            return updates;
        }

        try
        {
            // 1. Essayer avec la commande moderne 'winget list --upgrade-available'
            string output = await ExecuteWinGetCommandAsync(
                new[] { "list", "--upgrade-available", "--accept-source-agreements" }, 
                cancellationToken);

            var parsed = ParseWinGetOutput(output);
            if (parsed.Count == 0 && !output.Contains("---"))
            {
                // 2. Si la commande n'a pas retourné de tableau, repli sur 'winget list'
                output = await ExecuteWinGetCommandAsync(
                    new[] { "list", "--accept-source-agreements" }, 
                    cancellationToken);
                parsed = ParseWinGetOutput(output);
            }

            foreach (var kvp in parsed)
            {
                updates[kvp.Key] = kvp.Value;
            }
        }
        catch
        {
            // Tolérance aux pannes
        }

        return updates;
    }

    public async Task<IReadOnlyDictionary<string, SoftwareUpdateInfo>> DiscoverAllUpgradesAsync(
        CancellationToken cancellationToken = default)
    {
        var updates = new Dictionary<string, SoftwareUpdateInfo>(StringComparer.OrdinalIgnoreCase);

        if (!IsWinGetAvailable) return updates;

        try
        {
            string output = await ExecuteWinGetCommandAsync(
                new[] { "list", "--upgrade-available", "--accept-source-agreements" }, 
                cancellationToken);

            var parsed = ParseWinGetOutput(output);
            foreach (var kvp in parsed)
            {
                updates[kvp.Key] = kvp.Value;
            }
        }
        catch { }

        return updates;
    }

    public async Task<UpdateExecutionResult> ApplyUpdateAsync(
        string packageIdentifier, 
        IProgress<string>? consoleOutput = null, 
        CancellationToken cancellationToken = default)
    {
        if (!IsWinGetAvailable)
        {
            return new UpdateExecutionResult(false, string.Empty, "L'utilitaire WinGet n'est pas accessible sur cette machine.", -1);
        }

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = _wingetPath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            // Arguments d'exécution supervisée sans confirmation interactive
            startInfo.ArgumentList.Add("upgrade");
            startInfo.ArgumentList.Add("--id");
            startInfo.ArgumentList.Add(packageIdentifier);
            startInfo.ArgumentList.Add("--exact");
            startInfo.ArgumentList.Add("--accept-package-agreements");
            startInfo.ArgumentList.Add("--accept-source-agreements");
            startInfo.ArgumentList.Add("--silent");

            using var process = new Process { StartInfo = startInfo };
            var fullOutput = new System.Text.StringBuilder();

            process.OutputDataReceived += (_, e) =>
            {
                if (e.Data != null)
                {
                    fullOutput.AppendLine(e.Data);
                    consoleOutput?.Report(e.Data);
                }
            };

            process.ErrorDataReceived += (_, e) =>
            {
                if (e.Data != null)
                {
                    fullOutput.AppendLine("[ERR] " + e.Data);
                    consoleOutput?.Report("[ERR] " + e.Data);
                }
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            await process.WaitForExitAsync(cancellationToken);

            bool success = process.ExitCode == 0;
            string? errorMsg = success ? null : MapWinGetExitCode(process.ExitCode);

            return new UpdateExecutionResult(success, fullOutput.ToString(), errorMsg, process.ExitCode);
        }
        catch (Exception ex)
        {
            return new UpdateExecutionResult(false, string.Empty, ex.Message, -1);
        }
    }

    public async Task<UpdateExecutionResult> ApplyAllUpdatesAsync(
        IProgress<string>? consoleOutput = null, 
        CancellationToken cancellationToken = default)
    {
        if (!IsWinGetAvailable)
        {
            return new UpdateExecutionResult(false, string.Empty, "L'utilitaire WinGet n'est pas accessible sur cette machine.", -1);
        }

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = _wingetPath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            startInfo.ArgumentList.Add("upgrade");
            startInfo.ArgumentList.Add("--all");
            startInfo.ArgumentList.Add("--accept-package-agreements");
            startInfo.ArgumentList.Add("--accept-source-agreements");
            startInfo.ArgumentList.Add("--silent");

            using var process = new Process { StartInfo = startInfo };
            var fullOutput = new System.Text.StringBuilder();

            process.OutputDataReceived += (_, e) =>
            {
                if (e.Data != null)
                {
                    fullOutput.AppendLine(e.Data);
                    consoleOutput?.Report(e.Data);
                }
            };

            process.ErrorDataReceived += (_, e) =>
            {
                if (e.Data != null)
                {
                    fullOutput.AppendLine("[ERR] " + e.Data);
                    consoleOutput?.Report("[ERR] " + e.Data);
                }
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            await process.WaitForExitAsync(cancellationToken);

            bool success = process.ExitCode == 0;
            string? errorMsg = success ? null : MapWinGetExitCode(process.ExitCode);

            return new UpdateExecutionResult(success, fullOutput.ToString(), errorMsg, process.ExitCode);
        }
        catch (Exception ex)
        {
            return new UpdateExecutionResult(false, string.Empty, ex.Message, -1);
        }
    }

    public static Dictionary<string, SoftwareUpdateInfo> ParseWinGetOutput(string output)
    {
        var result = new Dictionary<string, SoftwareUpdateInfo>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(output)) return result;

        var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        // Chercher la ligne de séparation (ex: "------------------")
        int dataStartIndex = -1;
        for (int i = 0; i < lines.Length; i++)
        {
            if (lines[i].StartsWith("---") || lines[i].Contains("-------"))
            {
                dataStartIndex = i + 1;
                break;
            }
        }

        if (dataStartIndex == -1 || dataStartIndex >= lines.Length)
        {
            return result;
        }

        for (int i = dataStartIndex; i < lines.Length; i++)
        {
            string line = lines[i].Trim();
            if (string.IsNullOrWhiteSpace(line)) continue;

            // Découpage par colonnes multi-espaces
            var parts = Regex.Split(line, @"\s{2,}").ToList();
            if (parts.Count == 3)
            {
                var subTokens = parts[2].Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (subTokens.Length >= 2)
                {
                    parts.RemoveAt(2);
                    parts.AddRange(subTokens);
                }
            }

            if (parts.Count >= 4)
            {
                string name = parts[0].Trim();
                string id = parts[1].Trim();
                string currentVer = parts[2].Trim();
                string availableVer = parts[3].Trim();
                string source = parts.Count >= 5 ? parts[4].Trim() : "winget";

                // Si une version disponible distincte est signalée
                if (!string.IsNullOrWhiteSpace(availableVer) && availableVer != "<" && availableVer != currentVer)
                {
                    var updateInfo = new SoftwareUpdateInfo
                    {
                        ApplicationName = name,
                        PackageIdentifier = id,
                        CurrentVersion = currentVer,
                        AvailableVersion = availableVer,
                        SourceRepository = source,
                        Status = UpdateStatus.UpdateAvailable,
                        CheckedAt = DateTime.UtcNow
                    };

                    result[id] = updateInfo;
                    result[name] = updateInfo;
                }
            }
        }

        return result;
    }

    private async Task<string> ExecuteWinGetCommandAsync(IEnumerable<string> arguments, CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = _wingetPath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        foreach (var arg in arguments)
        {
            startInfo.ArgumentList.Add(arg);
        }

        using var process = new Process { StartInfo = startInfo };
        process.Start();

        string output = await process.StandardOutput.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);

        return output;
    }

    private bool CheckWinGetAvailability()
    {
        if (string.IsNullOrEmpty(_wingetPath)) return false;
        try
        {
            return File.Exists(_wingetPath);
        }
        catch
        {
            return false;
        }
    }

    public static string MapWinGetExitCode(int exitCode)
    {
        return (uint)exitCode switch
        {
            0 => "Opération terminée avec succès.",
            0x8A150011 => "Aucune mise à jour applicable trouvée pour ce package.",
            0x8A150005 => "Le package est déjà installé ou épinglé à cette version.",
            0x8A150014 => "L'installation a été annulée par l'utilisateur ou la stratégie système.",
            0x8A15002B => "Élévation de privilèges (Administrateur) requise pour installer ce package.",
            0x80070005 => "Accès refusé : privilèges insuffisants.",
            _ => $"Code retour WinGet : 0x{exitCode:X8} ({exitCode})"
        };
    }

    private static string ResolveWinGetExecutable()
    {
        // 1. Recherche dans le dossier WindowsApps local
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string defaultPath = Path.Combine(localAppData, @"Microsoft\WindowsApps\winget.exe");
        if (File.Exists(defaultPath)) return defaultPath;

        // 2. Recherche sécurisée via %SystemRoot%\System32\where.exe dans le PATH
        try
        {
            string systemDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
            string wherePath = Path.Combine(systemDir, "where.exe");
            if (File.Exists(wherePath))
            {
                var psi = new ProcessStartInfo
                {
                    FileName = wherePath,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };
                psi.ArgumentList.Add("winget.exe");

                var p = Process.Start(psi);
                if (p != null)
                {
                    string output = p.StandardOutput.ReadToEnd().Trim();
                    p.WaitForExit(2000);
                    if (p.ExitCode == 0 && !string.IsNullOrEmpty(output))
                    {
                        string firstPath = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty;
                        if (File.Exists(firstPath)) return firstPath;
                    }
                }
            }
        }
        catch { }

        return "winget.exe";
    }
}
