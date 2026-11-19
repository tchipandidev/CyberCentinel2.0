using System.Text.RegularExpressions;
using CyberSentinel.Domain.ValueObjects;

namespace CyberSentinel.Infrastructure.Vulnerabilities;

public class CpeResolver
{
    private static readonly (string Pattern, string Vendor, string Product)[] CuratedMappings =
    {
        ("Google Chrome", "google", "chrome"),
        ("Mozilla Firefox", "mozilla", "firefox"),
        ("VLC media player", "videolan", "vlc_media_player"),
        ("7-Zip", "7-zip", "7-zip"),
        ("Notepad\\+\\+", "notepad-plus-plus", "notepad++"),
        ("Git", "git-scm", "git"),
        ("Python", "python", "python"),
        ("WinRAR", "rarlab", "winrar"),
        ("Adobe Acrobat", "adobe", "acrobat_reader"),
        ("Visual Studio Code", "microsoft", "visual_studio_code"),
        ("Brave", "brave", "brave"),
        ("Wireshark", "wireshark", "wireshark"),
        ("Node\\.js", "nodejs", "node.js"),
        ("OpenVPN", "openvpn", "openvpn"),
        ("Microsoft Edge", "microsoft", "edge"),
        ("FileZilla", "filezilla-project", "filezilla_client"),
        ("KeePass", "keepass", "keepass"),
        ("Audacity", "audacityteam", "audacity"),
        ("OpenSSL", "openssl", "openssl"),
        ("PuTTY", "simon_tatham", "putty"),
        ("Apache", "apache", "http_server")
    };

    public CpeIdentifier Resolve(string displayName, string publisher, string displayVersion)
    {
        return ResolveWithConfidence(displayName, publisher, displayVersion).Cpe;
    }

    public (CpeIdentifier Cpe, bool IsCurated) ResolveWithConfidence(string displayName, string publisher, string displayVersion)
    {
        foreach (var (pattern, vendor, product) in CuratedMappings)
        {
            if (Regex.IsMatch(displayName, pattern, RegexOptions.IgnoreCase))
            {
                return (new CpeIdentifier
                {
                    Part = "a",
                    Vendor = vendor,
                    Product = product,
                    Version = CleanVersionString(displayVersion)
                }, true);
            }
        }

        // Résolution heuristique par défaut pour logiciels tiers non répertoriés
        string fallbackVendor = !string.IsNullOrWhiteSpace(publisher) && publisher != "Éditeur inconnu"
            ? publisher
            : displayName;

        return (new CpeIdentifier
        {
            Part = "a",
            Vendor = fallbackVendor,
            Product = displayName,
            Version = CleanVersionString(displayVersion)
        }, false);
    }

    public static string CleanVersionString(string rawVersion)
    {
        if (string.IsNullOrWhiteSpace(rawVersion) || 
            rawVersion.Equals("Non spécifiée", StringComparison.OrdinalIgnoreCase) ||
            rawVersion.Equals("Inconnue", StringComparison.OrdinalIgnoreCase))
        {
            return "*";
        }

        // Nettoie pour ne conserver que la partie numérique/point standard (ex: "3.0.11.0 (64-bit)" -> "3.0.11.0")
        var match = Regex.Match(rawVersion.Trim(), @"^(\d+(\.\d+)*)");
        return match.Success ? match.Value : rawVersion.Trim();
    }
}
