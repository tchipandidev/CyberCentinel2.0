using System.Text.RegularExpressions;

namespace CyberSentinel.Application.Security;

/// <summary>
/// Validateur de sécurité pour les chemins de fichiers sous Windows.
/// Prévient les attaques par traversée de répertoires (Path Traversal), les noms de périphériques réservés (DOS devices),
/// les flux de données alternatifs NTFS (ADS) et les chemins UNC non autorisés.
/// </summary>
public static class PathSecurityValidator
{
    // Noms de périphériques DOS réservés sous Windows (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    private static readonly HashSet<string> ReservedDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    private static readonly Regex DevicePrefixPattern = new(
        @"^(\\\[\?\.]\\|//[\?\.]/)", 
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Vérifie si un chemin est syntaxiquement sûr et ne présente aucun risque de traversée ou d'injection.
    /// </summary>
    public static bool IsPathSafe(string? path, out string? sanitizedPath, out string? errorMessage)
    {
        sanitizedPath = null;
        errorMessage = null;

        if (string.IsNullOrWhiteSpace(path))
        {
            errorMessage = "Le chemin fourni est vide ou composé uniquement d'espaces.";
            return false;
        }

        // 1. Détection de caractères de contrôle et null bytes
        if (path.IndexOf('\0') >= 0 || path.Any(c => char.IsControl(c) && c != '\t'))
        {
            errorMessage = "Le chemin contient des caractères de contrôle ou des octets nuls interdits.";
            return false;
        }

        // 2. Détection des flux de données alternatifs NTFS (ADS : ex. "file.txt:hidden.exe")
        // Sous Windows, un double point ':' est uniquement légitime après la lettre de lecteur (ex. "C:\")
        int firstColon = path.IndexOf(':');
        if (firstColon >= 0)
        {
            if (firstColon != 1 || !char.IsLetter(path[0]))
            {
                errorMessage = "Le chemin contient un séparateur de flux de données alternatif (NTFS ADS) non autorisé.";
                return false;
            }

            // S'il y a un second ':', c'est une tentative d'ADS
            if (path.IndexOf(':', firstColon + 1) >= 0)
            {
                errorMessage = "Le chemin contient un flux de données alternatif NTFS illicite.";
                return false;
            }
        }

        // 3. Détection des préfixes de périphériques physiques directs (\\.\ ou \\?\)
        if (DevicePrefixPattern.IsMatch(path))
        {
            errorMessage = "L'accès direct aux périphériques système (\\.\\ ou \\?\\) est proscrit pour des raisons de sécurité.";
            return false;
        }

        // 4. Canonicalisation du chemin absolu
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (Exception ex)
        {
            errorMessage = $"Impossible de résoudre le chemin canonique : {ex.Message}";
            return false;
        }

        // 5. Vérification des noms de périphériques DOS réservés (ex: C:\temp\CON.txt ou AUX)
        string fileName = Path.GetFileNameWithoutExtension(fullPath);
        if (ReservedDeviceNames.Contains(fileName))
        {
            errorMessage = $"Le chemin cible un nom de périphérique DOS réservé ({fileName}), susceptible de bloquer le sous-système Windows.";
            return false;
        }

        // Vérifier chaque segment du répertoire pour éviter "C:\temp\CON\file.txt"
        string[] segments = fullPath.Split(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var segment in segments)
        {
            string segWithoutExt = Path.GetFileNameWithoutExtension(segment);
            if (ReservedDeviceNames.Contains(segWithoutExt))
            {
                errorMessage = $"Le chemin contient un répertoire portant un nom de périphérique réservé ({segment}).";
                return false;
            }
        }

        sanitizedPath = fullPath;
        return true;
    }

    /// <summary>
    /// Vérifie qu'un chemin cible se situe strictement dans un répertoire racine autorisé (Anti-Path Traversal).
    /// </summary>
    public static bool IsWithinAllowedRoot(string path, string allowedRootDirectory)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(allowedRootDirectory))
        {
            return false;
        }

        try
        {
            string fullPath = Path.GetFullPath(path);
            string fullRoot = Path.GetFullPath(allowedRootDirectory);

            if (!fullRoot.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal))
            {
                fullRoot += Path.DirectorySeparatorChar;
            }

            return fullPath.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(fullPath, fullRoot.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Vérifie si un chemin cible un répertoire système Windows protégé (C:\Windows, System32, etc.)
    /// </summary>
    public static bool IsRestrictedSystemPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;

        try
        {
            string fullPath = Path.GetFullPath(path);
            string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string systemDir = Environment.GetFolderPath(Environment.SpecialFolder.System);

            if (!string.IsNullOrEmpty(windowsDir) && fullPath.StartsWith(windowsDir, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (!string.IsNullOrEmpty(systemDir) && fullPath.StartsWith(systemDir, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return false;
        }
        catch
        {
            return true;
        }
    }
}

