using System.Text.RegularExpressions;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Infrastructure.SystemIntegration;

public class InventoryReconciliationEngine
{
    public IReadOnlyList<InstalledApplication> Reconcile(
        IEnumerable<InstalledApplication> registryApps,
        IReadOnlyDictionary<string, SoftwareUpdateInfo>? wingetUpdates = null,
        IEnumerable<InstalledApplication>? appxApps = null)
    {
        var reconciledMap = new Dictionary<string, InstalledApplication>(StringComparer.OrdinalIgnoreCase);

        // 1. Ingestion des applications du Registre
        foreach (var regApp in registryApps)
        {
            string cleanName = NormalizeApplicationName(regApp.DisplayName);
            string archKey = regApp.Architecture.ToString();
            string key = $"{cleanName}__arch_{archKey}";

            if (!reconciledMap.TryGetValue(key, out var existing))
            {
                reconciledMap[key] = regApp;
            }
            else
            {
                // Fusion : Si une ruche HKLM 64 a plus d'informations qu'une autre ruche
                reconciledMap[key] = MergeRegistryApplications(existing, regApp);
            }
        }

        // 2. Ingestion des applications AppX (Windows Store)
        if (appxApps != null)
        {
            foreach (var appx in appxApps)
            {
                string cleanName = NormalizeApplicationName(appx.DisplayName);
                string key = $"{cleanName}__arch_{appx.Architecture}";

                if (!reconciledMap.ContainsKey(key))
                {
                    reconciledMap[key] = appx;
                }
            }
        }

        // 3. Rapprochement et enrichissement avec les identifiants WinGet
        if (wingetUpdates != null && wingetUpdates.Count > 0)
        {
            foreach (var app in reconciledMap.Values)
            {
                // Rapprochement par nom exact ou nom nettoyé
                if (wingetUpdates.TryGetValue(app.DisplayName, out var updateByName))
                {
                    app.PackageIdentifier = updateByName.PackageIdentifier;
                    app.AvailableUpdate = updateByName;
                }
                else
                {
                    // Rapprochement heuristique par nom de paquet
                    string simpleName = SimplifyForMatching(app.DisplayName);
                    foreach (var kvp in wingetUpdates)
                    {
                        string wingetPkgName = SimplifyForMatching(kvp.Key);
                        if (simpleName.Equals(wingetPkgName, StringComparison.OrdinalIgnoreCase) ||
                            (simpleName.Length > 4 && wingetPkgName.Contains(simpleName, StringComparison.OrdinalIgnoreCase)))
                        {
                            app.PackageIdentifier = kvp.Value.PackageIdentifier;
                            app.AvailableUpdate = kvp.Value;
                            break;
                        }
                    }
                }
            }
        }

        return reconciledMap.Values
            .OrderBy(a => a.DisplayName)
            .ToList();
    }

    public static string NormalizeApplicationName(string rawName)
    {
        if (string.IsNullOrWhiteSpace(rawName)) return "Application inconnue";

        string cleaned = rawName.Trim();
        // Supprimer les suffixes de révision ou d'architecture redondants dans le nom (ex: " (64-bit)", " (x64)")
        cleaned = Regex.Replace(cleaned, @"\s*\((64-bit|32-bit|x64|x86)\)$", string.Empty, RegexOptions.IgnoreCase);
        // Nettoyer les espaces multiples
        cleaned = Regex.Replace(cleaned, @"\s{2,}", " ");
        return cleaned.Trim();
    }

    public static string SimplifyForMatching(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return string.Empty;
        return Regex.Replace(text.ToLowerInvariant(), @"[^a-z0-9]", string.Empty);
    }

    private static InstalledApplication MergeRegistryApplications(InstalledApplication primary, InstalledApplication secondary)
    {
        string version = primary.HasKnownVersion ? primary.DisplayVersion : secondary.DisplayVersion;
        string publisher = primary.HasKnownPublisher ? primary.Publisher : secondary.Publisher;
        string location = !string.IsNullOrWhiteSpace(primary.InstallLocation) ? primary.InstallLocation : secondary.InstallLocation;
        DateTime? installDate = primary.InstallDate ?? secondary.InstallDate;

        return new InstalledApplication
        {
            Id = primary.Id,
            DisplayName = primary.DisplayName,
            Publisher = publisher,
            DisplayVersion = version,
            Architecture = primary.Architecture != AppArchitecture.Unknown ? primary.Architecture : secondary.Architecture,
            InstallDate = installDate,
            InstallLocation = location,
            IdentificationSource = $"{primary.IdentificationSource} + {secondary.IdentificationSource}",
            RegistryHive = primary.RegistryHive,
            PackageIdentifier = primary.PackageIdentifier ?? secondary.PackageIdentifier,
            CanonicalCpe = primary.CanonicalCpe ?? secondary.CanonicalCpe,
            UninstallString = primary.UninstallString ?? secondary.UninstallString,
            IsSystemComponent = primary.IsSystemComponent && secondary.IsSystemComponent,
            DiscoveredAt = primary.DiscoveredAt
        };
    }
}

