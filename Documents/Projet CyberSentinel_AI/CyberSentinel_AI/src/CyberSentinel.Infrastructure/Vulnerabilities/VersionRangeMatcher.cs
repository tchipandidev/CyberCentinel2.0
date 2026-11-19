using System.Text.RegularExpressions;

namespace CyberSentinel.Infrastructure.Vulnerabilities;

public static class VersionRangeMatcher
{
    public static bool IsVulnerable(
        string installedVersion,
        string? versionStartIncluding = null,
        string? versionStartExcluding = null,
        string? versionEndIncluding = null,
        string? versionEndExcluding = null)
    {
        if (string.IsNullOrWhiteSpace(installedVersion))
        {
            return false;
        }

        var installedParts = ParseVersionSegments(installedVersion);
        if (installedParts.Count == 0) return false;

        // 1. Contrôle borne inférieure incluse
        if (!string.IsNullOrWhiteSpace(versionStartIncluding))
        {
            var startInc = ParseVersionSegments(versionStartIncluding);
            if (CompareSegments(installedParts, startInc) < 0) return false;
        }

        // 2. Contrôle borne inférieure exclue
        if (!string.IsNullOrWhiteSpace(versionStartExcluding))
        {
            var startExc = ParseVersionSegments(versionStartExcluding);
            if (CompareSegments(installedParts, startExc) <= 0) return false;
        }

        // 3. Contrôle borne supérieure incluse
        if (!string.IsNullOrWhiteSpace(versionEndIncluding))
        {
            var endInc = ParseVersionSegments(versionEndIncluding);
            if (CompareSegments(installedParts, endInc) > 0) return false;
        }

        // 4. Contrôle borne supérieure exclue
        if (!string.IsNullOrWhiteSpace(versionEndExcluding))
        {
            var endExc = ParseVersionSegments(versionEndExcluding);
            if (CompareSegments(installedParts, endExc) >= 0) return false;
        }

        return true;
    }

    public static List<int> ParseVersionSegments(string versionStr)
    {
        var segments = new List<int>();
        var matches = Regex.Matches(versionStr, @"\d+");
        foreach (Match match in matches)
        {
            if (int.TryParse(match.Value, out int val))
            {
                segments.Add(val);
            }
        }
        return segments;
    }

    public static int CompareSegments(List<int> left, List<int> right)
    {
        int max = Math.Max(left.Count, right.Count);
        for (int i = 0; i < max; i++)
        {
            int lVal = i < left.Count ? left[i] : 0;
            int rVal = i < right.Count ? right[i] : 0;

            if (lVal < rVal) return -1;
            if (lVal > rVal) return 1;
        }
        return 0;
    }
}

