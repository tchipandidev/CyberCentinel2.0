using System.Text;

namespace CyberSentinel.AI.Features;

public class PeFeatures
{
    public bool IsValidPe { get; set; }
    public long FileSizeBytes { get; set; }
    public double ShannonEntropy { get; set; }
    public int NumberOfSections { get; set; }
    public bool HasSuspiciousSectionNames { get; set; }
    public bool HasHighEntropySections { get; set; }
    public double MaxSectionEntropy { get; set; }
    public int SuspiciousApiCount { get; set; }
    public List<string> DetectedSuspiciousApis { get; set; } = new();
    public List<string> SectionNames { get; set; } = new();
    public bool HasUnpackingDiscrepancy { get; set; }
    public float CompositeHeuristicScore { get; set; }
}

public static class PeFeatureExtractor
{
    private static readonly HashSet<string> PackerSectionNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".fsg", ".themida", ".vmp0", ".vmp1", ".packer", "PECompact2"
    };

    private static readonly string[] SuspiciousApis =
    {
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
        "SetWindowsHookEx", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "URLDownloadToFile", "InternetOpenUrl", "HttpSendRequest",
        "RegCreateKeyEx", "RegSetValueEx", "CryptEncrypt", "CryptDecrypt",
        "AdjustTokenPrivileges", "OpenProcessToken"
    };

    public static async Task<PeFeatures> ExtractAsync(string filePath, CancellationToken cancellationToken = default)
    {
        var features = new PeFeatures();

        if (!File.Exists(filePath))
        {
            return features;
        }

        var fileInfo = new FileInfo(filePath);
        features.FileSizeBytes = fileInfo.Length;

        // Limite de lecture pour l'analyse (max 50 Mo)
        int readSize = (int)Math.Min(features.FileSizeBytes, 50 * 1024 * 1024);
        byte[] buffer = new byte[readSize];

        using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            await fs.ReadExactlyAsync(buffer, 0, readSize, cancellationToken);
        }

        // 1. Validation de la signature PE (DOS header MZ et NT signature PE\0\0)
        if (buffer.Length < 64 || buffer[0] != 'M' || buffer[1] != 'Z')
        {
            return features;
        }

        int peHeaderOffset = BitConverter.ToInt32(buffer, 0x3C);
        if (peHeaderOffset < 0 || peHeaderOffset + 4 >= buffer.Length)
        {
            return features;
        }

        if (buffer[peHeaderOffset] != 'P' || buffer[peHeaderOffset + 1] != 'E' ||
            buffer[peHeaderOffset + 2] != 0 || buffer[peHeaderOffset + 3] != 0)
        {
            return features;
        }

        features.IsValidPe = true;

        // 2. Calcul de l'entropie globale de Shannon
        features.ShannonEntropy = ComputeShannonEntropy(buffer);

        // 3. Analyse des sections PE
        int fileHeaderOffset = peHeaderOffset + 4;
        int numberOfSections = BitConverter.ToInt16(buffer, fileHeaderOffset + 2);
        features.NumberOfSections = numberOfSections;

        int sizeOfOptionalHeader = BitConverter.ToInt16(buffer, fileHeaderOffset + 16);
        int sectionHeadersOffset = fileHeaderOffset + 20 + sizeOfOptionalHeader;

        double maxEntropy = 0.0;
        bool hasPackerName = false;
        bool hasUnpackDiscrepancy = false;

        for (int i = 0; i < numberOfSections; i++)
        {
            int sectionOffset = sectionHeadersOffset + (i * 40);
            if (sectionOffset + 40 > buffer.Length) break;

            // Nom de la section (8 octets ASCII)
            string secName = Encoding.ASCII.GetString(buffer, sectionOffset, 8).TrimEnd('\0').Trim();
            features.SectionNames.Add(secName);

            if (PackerSectionNames.Contains(secName))
            {
                hasPackerName = true;
            }

            int virtualSize = BitConverter.ToInt32(buffer, sectionOffset + 8);
            int rawDataSize = BitConverter.ToInt32(buffer, sectionOffset + 16);
            int rawDataPointer = BitConverter.ToInt32(buffer, sectionOffset + 20);

            // Vérification de discordance typique d'unpacking (VirtualSize >> RawSize avec rawSize > 0)
            if (rawDataSize > 0 && virtualSize > rawDataSize * 3)
            {
                hasUnpackDiscrepancy = true;
            }

            // Calcul d'entropie locale de la section
            if (rawDataPointer > 0 && rawDataSize > 0 && rawDataPointer + rawDataSize <= buffer.Length)
            {
                double secEntropy = ComputeShannonEntropy(buffer, rawDataPointer, rawDataSize);
                if (secEntropy > maxEntropy) maxEntropy = secEntropy;
            }
        }

        features.MaxSectionEntropy = maxEntropy;
        features.HasSuspiciousSectionNames = hasPackerName;
        features.HasHighEntropySections = maxEntropy >= 7.2;
        features.HasUnpackingDiscrepancy = hasUnpackDiscrepancy;

        // 4. Recherche de signatures de chaînes d'APIs critiques
        string asciiContent = Encoding.ASCII.GetString(buffer);
        foreach (var api in SuspiciousApis)
        {
            if (asciiContent.Contains(api, StringComparison.OrdinalIgnoreCase))
            {
                features.DetectedSuspiciousApis.Add(api);
            }
        }
        features.SuspiciousApiCount = features.DetectedSuspiciousApis.Count;

        // 5. Calcul du score heuristique composite (0.0 à 1.0)
        float score = 0.05f;

        if (features.HasSuspiciousSectionNames) score += 0.35f;
        if (features.HasHighEntropySections) score += 0.25f;
        if (features.HasUnpackingDiscrepancy) score += 0.20f;
        if (features.ShannonEntropy > 7.0) score += 0.15f;

        if (features.SuspiciousApiCount >= 4) score += 0.30f;
        else if (features.SuspiciousApiCount >= 2) score += 0.15f;

        features.CompositeHeuristicScore = Math.Clamp(score, 0.0f, 0.99f);

        return features;
    }

    public static double ComputeShannonEntropy(byte[] data, int offset = 0, int length = -1)
    {
        if (length == -1) length = data.Length;
        if (length == 0) return 0.0;

        int[] frequencies = new int[256];
        int end = offset + length;
        for (int i = offset; i < end; i++)
        {
            frequencies[data[i]]++;
        }

        double entropy = 0.0;
        double len = length;

        for (int i = 0; i < 256; i++)
        {
            if (frequencies[i] > 0)
            {
                double p = frequencies[i] / len;
                entropy -= p * Math.Log2(p);
            }
        }

        return entropy;
    }
}

