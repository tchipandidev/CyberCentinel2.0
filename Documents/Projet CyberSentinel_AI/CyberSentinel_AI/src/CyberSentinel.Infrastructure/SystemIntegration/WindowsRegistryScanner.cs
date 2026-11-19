using System.Globalization;
using System.Runtime.Versioning;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;
using Microsoft.Win32;

namespace CyberSentinel.Infrastructure.SystemIntegration;

[SupportedOSPlatform("windows")]
public class WindowsRegistryScanner : ISystemInventoryService
{
    private static readonly (RegistryHive Hive, string SubKey, string SourceLabel, AppArchitecture Arch)[] RegistryTargets =
    {
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "Registry_HKLM_64", AppArchitecture.X64),
        (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "Registry_HKLM_32", AppArchitecture.X86),
        (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Uninstall", "Registry_HKCU", AppArchitecture.Neutral)
    };

    public Task<IReadOnlyList<InstalledApplication>> GetInstalledApplicationsAsync(CancellationToken cancellationToken = default) =>
        GetInstalledApplicationsAsync(null, cancellationToken);

    public Task<IReadOnlyList<InstalledApplication>> GetInstalledApplicationsAsync(
        IProgress<(string Step, int Percent)>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var applications = new List<InstalledApplication>();
        int totalTargets = RegistryTargets.Length;
        int currentTarget = 0;

        foreach (var (hive, subKeyPath, sourceLabel, defaultArch) in RegistryTargets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            currentTarget++;
            progress?.Report(($"Lecture ruche {sourceLabel}...", (currentTarget * 100) / totalTargets));

            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var subKey = baseKey.OpenSubKey(subKeyPath);
                if (subKey == null) continue;

                foreach (string subKeyName in subKey.GetSubKeyNames())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    try
                    {
                        using var appKey = subKey.OpenSubKey(subKeyName);
                        if (appKey == null) continue;

                        string? displayName = appKey.GetValue("DisplayName") as string;
                        if (string.IsNullOrWhiteSpace(displayName)) continue;

                        // Filtrage des composants système masqués
                        int? isSystemComponent = appKey.GetValue("SystemComponent") as int?;
                        if (isSystemComponent == 1) continue;

                        // Ignorer les sous-mises à jour qui pointent vers une clé parente
                        string? parentKeyName = appKey.GetValue("ParentKeyName") as string;
                        if (!string.IsNullOrEmpty(parentKeyName)) continue;

                        string publisher = (appKey.GetValue("Publisher") as string)?.Trim() ?? "Éditeur inconnu";
                        string version = (appKey.GetValue("DisplayVersion") as string)?.Trim() ?? "Non spécifiée";
                        string installLocation = (appKey.GetValue("InstallLocation") as string)?.Trim() ?? string.Empty;
                        string uninstallString = (appKey.GetValue("UninstallString") as string)?.Trim() ?? string.Empty;

                        // Extraction et parsing robuste de la date d'installation (format YYYYMMDD fréquent)
                        DateTime? installDate = ParseRegistryInstallDate(appKey.GetValue("InstallDate") as string);

                        // Raffinement de l'architecture pour HKCU
                        AppArchitecture arch = defaultArch;
                        if (arch == AppArchitecture.Neutral && !string.IsNullOrWhiteSpace(installLocation))
                        {
                            if (installLocation.Contains("Program Files (x86)", StringComparison.OrdinalIgnoreCase))
                            {
                                arch = AppArchitecture.X86;
                            }
                            else if (installLocation.Contains("Program Files", StringComparison.OrdinalIgnoreCase))
                            {
                                arch = AppArchitecture.X64;
                            }
                        }

                        applications.Add(new InstalledApplication
                        {
                            DisplayName = displayName.Trim(),
                            Publisher = publisher,
                            DisplayVersion = version,
                            Architecture = arch,
                            InstallDate = installDate,
                            InstallLocation = installLocation,
                            IdentificationSource = sourceLabel,
                            RegistryHive = sourceLabel,
                            UninstallString = uninstallString,
                            IsSystemComponent = false,
                            DiscoveredAt = DateTime.UtcNow
                        });
                    }
                    catch
                    {
                        // Continuer si une sous-clé est protégée
                    }
                }
            }
            catch
            {
                // Continuer si une ruche est inaccessible
            }
        }

        return Task.FromResult<IReadOnlyList<InstalledApplication>>(applications);
    }

    public static DateTime? ParseRegistryInstallDate(string? rawDate)
    {
        if (string.IsNullOrWhiteSpace(rawDate)) return null;

        string cleanDate = rawDate.Trim();

        // Format standard Windows Registry : YYYYMMDD (ex: "20240512")
        if (cleanDate.Length == 8 && DateTime.TryParseExact(cleanDate, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt))
        {
            return dt;
        }

        // Format ISO / standard (ex: "2024-05-12" ou "12/05/2024")
        if (DateTime.TryParse(cleanDate, CultureInfo.CurrentCulture, DateTimeStyles.None, out var parsed))
        {
            return parsed;
        }

        return null;
    }
}
