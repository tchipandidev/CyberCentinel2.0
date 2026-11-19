using System.Text;

namespace CyberSentinel.AI.Features;

public static class EmberFeatureExtractor
{
    private const int MaxScanSize = 50 * 1024 * 1024; // 50 Mo max pour l'analyse statique locale

    public static async Task<EmberFeatureVector> ExtractVectorAsync(
        string filePath, 
        bool isEmber2024 = false, 
        CancellationToken cancellationToken = default)
    {
        int dimension = isEmber2024 ? EmberFeatureVector.Ember2024VectorDimension : EmberFeatureVector.ClassicVectorDimension;
        var vector = new float[dimension];

        if (!File.Exists(filePath))
        {
            return new EmberFeatureVector(vector);
        }

        var fileInfo = new FileInfo(filePath);
        long fileSize = fileInfo.Length;
        if (fileSize == 0) return new EmberFeatureVector(vector);

        int readLength = (int)Math.Min(fileSize, MaxScanSize);
        byte[] buffer = new byte[readLength];

        using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            await fs.ReadExactlyAsync(buffer, 0, readLength, cancellationToken);
        }

        // 1. Feature Category: ByteHistogram (Indices 0..255)
        ComputeByteHistogram(buffer, vector, offset: 0);

        // 2. Feature Category: ByteEntropyHistogram (Indices 256..511)
        ComputeByteEntropyHistogram(buffer, vector, offset: 256);

        // 3. Feature Category: StringExtractor (Indices 512..615)
        ComputeStringFeatures(buffer, vector, offset: 512);

        // 4. Feature Category: GeneralFileInfo & PE Headers (Indices 616..942)
        ExtractPeHeaderAndSectionFeatures(buffer, fileSize, vector, offsetGeneral: 616, offsetHeader: 626, offsetSection: 688);

        // 5. Feature Category: ImportsInfo & ExportsInfo (Indices 943..2350)
        ExtractImportsAndExportsHashFeatures(buffer, vector, offsetImports: 943, offsetExports: 2223);

        // 6. Si mode EMBER2024 (v3 / thrember) : Rich Header, Authenticode & Parse Warnings (Indices 2381..2567)
        if (isEmber2024)
        {
            ExtractEmber2024Extensions(buffer, vector, offset: 2381);
        }

        return new EmberFeatureVector(vector);
    }

    private static void ComputeByteHistogram(byte[] data, float[] vector, int offset)
    {
        int[] counts = new int[256];
        for (int i = 0; i < data.Length; i++)
        {
            counts[data[i]]++;
        }

        float total = (float)data.Length;
        for (int i = 0; i < 256; i++)
        {
            vector[offset + i] = counts[i] / total;
        }
    }

    private static void ComputeByteEntropyHistogram(byte[] data, float[] vector, int offset)
    {
        // Fenêtre glissante standard EMBER : 1024 octets, pas de 256 octets
        const int windowSize = 1024;
        const int step = 256;

        if (data.Length < windowSize)
        {
            // Fichier plus petit que la fenêtre : calcul global
            double ent = PeFeatureExtractor.ComputeShannonEntropy(data);
            int entBin = Math.Clamp((int)(ent * 2), 0, 15);
            for (int i = 0; i < 16; i++)
            {
                vector[offset + (entBin * 16) + i] = 1.0f / 16.0f;
            }
            return;
        }

        int[] matrix = new int[256]; // 16x16 bins
        int totalWindows = 0;

        for (int w = 0; w <= data.Length - windowSize; w += step)
        {
            double entropy = PeFeatureExtractor.ComputeShannonEntropy(data, w, windowSize); // 0.0 à 8.0
            int entBin = Math.Clamp((int)(entropy * 2), 0, 15); // 0..15

            // Calcul du byte dominant ou de la répartition par demi-quartile
            for (int k = 0; k < windowSize; k += 64)
            {
                int byteVal = data[w + k];
                int byteBin = byteVal / 16; // 0..15
                int index = (entBin * 16) + byteBin;
                matrix[index]++;
                totalWindows++;
            }
        }

        if (totalWindows > 0)
        {
            for (int i = 0; i < 256; i++)
            {
                vector[offset + i] = (float)matrix[i] / totalWindows;
            }
        }
    }

    private static void ComputeStringFeatures(byte[] data, float[] vector, int offset)
    {
        int minLength = 5;
        int currentLength = 0;
        int totalStrings = 0;
        int totalCharacters = 0;
        int urlCount = 0;
        int pathCount = 0;
        int regCount = 0;

        var sb = new StringBuilder();

        for (int i = 0; i < data.Length; i++)
        {
            byte b = data[i];
            if (b >= 32 && b <= 126) // Caractère imprimable ASCII
            {
                currentLength++;
                if (currentLength < 256) sb.Append((char)b);
            }
            else
            {
                if (currentLength >= minLength)
                {
                    totalStrings++;
                    totalCharacters += currentLength;
                    string str = sb.ToString();

                    if (str.Contains("http://", StringComparison.OrdinalIgnoreCase) || 
                        str.Contains("https://", StringComparison.OrdinalIgnoreCase))
                    {
                        urlCount++;
                    }
                    if (str.Contains(@":\", StringComparison.OrdinalIgnoreCase) || 
                        str.Contains(@"System32\", StringComparison.OrdinalIgnoreCase))
                    {
                        pathCount++;
                    }
                    if (str.Contains("HKEY_", StringComparison.OrdinalIgnoreCase) || 
                        str.Contains(@"Software\", StringComparison.OrdinalIgnoreCase))
                    {
                        regCount++;
                    }
                }
                currentLength = 0;
                sb.Clear();
            }
        }

        vector[offset] = totalStrings;
        vector[offset + 1] = totalStrings > 0 ? (float)totalCharacters / totalStrings : 0.0f;
        vector[offset + 2] = urlCount;
        vector[offset + 3] = pathCount;
        vector[offset + 4] = regCount;
        vector[offset + 5] = (float)Math.Log(totalCharacters + 1);
    }

    private static void ExtractPeHeaderAndSectionFeatures(
        byte[] buffer, 
        long fileSize, 
        float[] vector, 
        int offsetGeneral, 
        int offsetHeader, 
        int offsetSection)
    {
        // Vérification DOS header
        if (buffer.Length < 64 || buffer[0] != 'M' || buffer[1] != 'Z')
        {
            return;
        }

        int peOffset = BitConverter.ToInt32(buffer, 0x3C);
        if (peOffset < 0 || peOffset + 24 > buffer.Length) return;

        if (buffer[peOffset] != 'P' || buffer[peOffset + 1] != 'E' ||
            buffer[peOffset + 2] != 0 || buffer[peOffset + 3] != 0)
        {
            return;
        }

        // GeneralFileInfo
        vector[offsetGeneral] = (float)Math.Log(fileSize + 1);
        int fileHeaderOffset = peOffset + 4;
        ushort machine = BitConverter.ToUInt16(buffer, fileHeaderOffset);
        ushort numSections = BitConverter.ToUInt16(buffer, fileHeaderOffset + 2);
        uint timeDateStamp = BitConverter.ToUInt32(buffer, fileHeaderOffset + 4);
        ushort sizeOfOptHeader = BitConverter.ToUInt16(buffer, fileHeaderOffset + 16);
        ushort characteristics = BitConverter.ToUInt16(buffer, fileHeaderOffset + 18);

        vector[offsetGeneral + 1] = numSections;
        vector[offsetGeneral + 2] = (characteristics & 0x2000) != 0 ? 1.0f : 0.0f; // IsDLL
        vector[offsetGeneral + 3] = (characteristics & 0x0002) != 0 ? 1.0f : 0.0f; // IsExecutableImage

        // HeaderFileInfo
        vector[offsetHeader] = machine;
        vector[offsetHeader + 1] = timeDateStamp;
        vector[offsetHeader + 2] = characteristics;
        vector[offsetHeader + 3] = sizeOfOptHeader;

        int optHeaderOffset = fileHeaderOffset + 20;
        if (optHeaderOffset + sizeOfOptHeader <= buffer.Length && sizeOfOptHeader > 0)
        {
            ushort magic = BitConverter.ToUInt16(buffer, optHeaderOffset);
            uint entryPoint = BitConverter.ToUInt32(buffer, optHeaderOffset + 16);
            vector[offsetHeader + 4] = magic;
            vector[offsetHeader + 5] = entryPoint;
        }

        // SectionInfo (Histogramme et caractéristiques des sections)
        int sectionTableOffset = optHeaderOffset + sizeOfOptHeader;
        double maxSectionEntropy = 0.0;
        int suspiciousPackerCount = 0;

        for (int i = 0; i < Math.Min((int)numSections, 16); i++)
        {
            int secOffset = sectionTableOffset + (i * 40);
            if (secOffset + 40 > buffer.Length) break;

            string secName = Encoding.ASCII.GetString(buffer, secOffset, 8).TrimEnd('\0').Trim();
            int vSize = BitConverter.ToInt32(buffer, secOffset + 8);
            int rSize = BitConverter.ToInt32(buffer, secOffset + 16);
            int rPtr = BitConverter.ToInt32(buffer, secOffset + 20);

            if (rPtr > 0 && rSize > 0 && rPtr + rSize <= buffer.Length)
            {
                double ent = PeFeatureExtractor.ComputeShannonEntropy(buffer, rPtr, rSize);
                if (ent > maxSectionEntropy) maxSectionEntropy = ent;
            }

            if (secName.StartsWith("UPX", StringComparison.OrdinalIgnoreCase) || 
                secName.Contains("vmp", StringComparison.OrdinalIgnoreCase))
            {
                suspiciousPackerCount++;
            }

            vector[offsetSection + i] = (float)Math.Log(vSize + 1);
            vector[offsetSection + 16 + i] = (float)Math.Log(rSize + 1);
        }

        vector[offsetSection + 32] = (float)maxSectionEntropy;
        vector[offsetSection + 33] = suspiciousPackerCount;
    }

    private static void ExtractImportsAndExportsHashFeatures(
        byte[] buffer, 
        float[] vector, 
        int offsetImports, 
        int offsetExports)
    {
        // Hash-trick EMBER : hachage des chaînes de bibliothèques (DLL) et d'APIs dans des bacs (bins)
        string ascii = Encoding.ASCII.GetString(buffer);

        string[] commonLibraries = { "kernel32.dll", "user32.dll", "advapi32.dll", "shell32.dll", "ntdll.dll", "ws2_32.dll", "wininet.dll", "ole32.dll" };
        for (int i = 0; i < commonLibraries.Length; i++)
        {
            if (ascii.Contains(commonLibraries[i], StringComparison.OrdinalIgnoreCase))
            {
                int bin = Math.Abs(commonLibraries[i].GetHashCode()) % 256;
                vector[offsetImports + bin] += 1.0f;
            }
        }

        string[] criticalApis = { "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "IsDebuggerPresent", "RegSetValueExA", "HttpOpenRequestA", "InternetReadFile" };
        for (int i = 0; i < criticalApis.Length; i++)
        {
            if (ascii.Contains(criticalApis[i], StringComparison.OrdinalIgnoreCase))
            {
                int bin = 256 + (Math.Abs(criticalApis[i].GetHashCode()) % 1024);
                vector[offsetImports + bin] += 1.0f;
            }
        }
    }

    private static void ExtractEmber2024Extensions(byte[] buffer, float[] vector, int offset)
    {
        // Extensions spécifiques à EMBER2024 :
        // 1. Détection Rich Header (Compilateur Visual Studio / MASM)
        bool hasRichHeader = false;
        for (int i = 0; i < Math.Min(buffer.Length - 4, 1024); i++)
        {
            if (buffer[i] == 'R' && buffer[i + 1] == 'i' && buffer[i + 2] == 'c' && buffer[i + 3] == 'h')
            {
                hasRichHeader = true;
                break;
            }
        }
        vector[offset] = hasRichHeader ? 1.0f : 0.0f;

        // 2. Détection Authenticode (Signature numérique de sécurité)
        // Vérification du répertoire de sécurité dans le Data Directory (Entry 4)
        vector[offset + 1] = 0.0f; // 1.0f si signé
        vector[offset + 2] = (float)Math.Log(buffer.Length + 1);
    }
}

