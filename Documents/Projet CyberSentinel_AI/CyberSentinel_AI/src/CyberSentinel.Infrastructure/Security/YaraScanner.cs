using System.Diagnostics;
using System.Text.RegularExpressions;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.Security;
using CyberSentinel.Domain.Entities;
using CyberSentinel.Domain.Enums;

namespace CyberSentinel.Infrastructure.Security;

public class YaraRuleDefinition
{
    public string Name { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public RiskLevel Severity { get; init; } = RiskLevel.Medium;
    public string ThreatType { get; init; } = "Generic";
    public List<byte[]> BytePatterns { get; init; } = new();
    public List<string> StringPatterns { get; init; } = new();
    public List<Regex> RegexPatterns { get; init; } = new();
    public bool RequiresAllPatterns { get; init; }
}

public class YaraScanner : IYaraScanner
{
    private readonly List<YaraRuleDefinition> _rules = new();
    private readonly string _yaraBinaryPath;

    public string EngineName => "YARA Heuristic Engine";
    public int LoadedRulesCount => _rules.Count;

    public YaraScanner(string? yaraBinaryPath = null, string? rulesDirectory = null)
    {
        _yaraBinaryPath = ResolveYaraBinary(yaraBinaryPath);
        RegisterBuiltinRules();

        if (!string.IsNullOrEmpty(rulesDirectory) && Directory.Exists(rulesDirectory))
        {
            LoadRulesFromDirectoryAsync(rulesDirectory).GetAwaiter().GetResult();
        }
    }

    public async Task<int> LoadRulesFromDirectoryAsync(string directoryPath, CancellationToken cancellationToken = default)
    {
        if (!PathSecurityValidator.IsPathSafe(directoryPath, out string? safeDir, out _))
        {
            return _rules.Count;
        }

        directoryPath = safeDir!;

        if (!Directory.Exists(directoryPath))
        {
            return _rules.Count;
        }

        var ruleFiles = Directory.EnumerateFiles(directoryPath, "*.yar*", SearchOption.AllDirectories);
        int added = 0;

        foreach (var file in ruleFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var fi = new FileInfo(file);
                // Protection contre l'épuisement mémoire (Règles max 5 Mo)
                if (fi.Length > 5 * 1024 * 1024) continue;

                string content = await File.ReadAllTextAsync(file, cancellationToken);
                var parsedRules = ParseYaraRuleContent(content);
                _rules.AddRange(parsedRules);
                added += parsedRules.Count;
            }
            catch
            {
                // Ignorer les fichiers de règles malformés pour ne pas faire planter l'application
            }
        }

        return _rules.Count;
    }

    public async Task<EngineScanResult> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();

        if (!File.Exists(filePath))
        {
            return EngineScanResult.Failure(EngineType.YARA, $"Fichier introuvable : {filePath}");
        }

        try
        {
            // 1. Si le binaire officiel yara64.exe est présent, l'utiliser en priorité
            if (!string.IsNullOrEmpty(_yaraBinaryPath) && File.Exists(_yaraBinaryPath))
            {
                var cliResult = await ScanWithYaraCliAsync(filePath, cancellationToken);
                if (cliResult != null)
                {
                    stopwatch.Stop();
                    return cliResult;
                }
            }

            // 2. Moteur managé natif C# ultra-rapide
            byte[] fileBytes;
            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                // Limite d'analyse en mémoire pour éviter OutOfMemoryException (50 Mo max)
                int readLength = (int)Math.Min(stream.Length, 50 * 1024 * 1024);
                fileBytes = new byte[readLength];
                stream.ReadExactly(fileBytes, 0, readLength);
            }

            var matchedRules = new List<YaraRuleDefinition>();

            foreach (var rule in _rules)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (EvaluateRule(rule, fileBytes))
                {
                    matchedRules.Add(rule);
                }
            }

            stopwatch.Stop();

            if (matchedRules.Count == 0)
            {
                return EngineScanResult.Success(
                    EngineType.YARA,
                    ThreatVerdict.Clean,
                    RiskLevel.None,
                    null,
                    $"Aucune règle YARA déclenchée ({_rules.Count} règles évaluées).",
                    stopwatch.ElapsedMilliseconds);
            }

            // Évaluation contextuelle des correspondances :
            // Ne pas considérer une simple correspondance textuelle comme une preuve de malware !
            var highestSeverity = matchedRules.Max(r => r.Severity);
            var criticalRule = matchedRules.FirstOrDefault(r => r.Severity >= RiskLevel.High) ?? matchedRules.First();

            ThreatVerdict verdict;
            if (highestSeverity >= RiskLevel.High)
            {
                verdict = ThreatVerdict.Malicious;
            }
            else if (highestSeverity == RiskLevel.Medium)
            {
                verdict = ThreatVerdict.Suspicious;
            }
            else
            {
                // Correspondances purement informatives ou heuristiques faibles
                verdict = ThreatVerdict.Clean;
            }

            string matchedNames = string.Join(", ", matchedRules.Select(r => r.Name));
            string details = $"Règles déclenchées : {matchedNames}. Règle principale : {criticalRule.Name} ({criticalRule.Description})";

            return EngineScanResult.Success(
                EngineType.YARA,
                verdict,
                highestSeverity,
                criticalRule.Name,
                details,
                stopwatch.ElapsedMilliseconds);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            return EngineScanResult.Failure(
                EngineType.YARA, 
                $"Erreur lors de l'analyse YARA : {ex.Message}", 
                stopwatch.ElapsedMilliseconds);
        }
    }

    private static bool EvaluateRule(YaraRuleDefinition rule, byte[] fileBytes)
    {
        // 1. Byte patterns (Hex strings)
        bool byteMatches = rule.BytePatterns.Count == 0 ||
            (rule.RequiresAllPatterns 
                ? rule.BytePatterns.All(p => IndexOfSequence(fileBytes, p) >= 0)
                : rule.BytePatterns.Any(p => IndexOfSequence(fileBytes, p) >= 0));

        if (rule.RequiresAllPatterns && !byteMatches) return false;

        // 2. String patterns
        bool stringMatches = true;
        if (rule.StringPatterns.Count > 0)
        {
            string contentAscii = System.Text.Encoding.ASCII.GetString(fileBytes);
            stringMatches = rule.RequiresAllPatterns
                ? rule.StringPatterns.All(s => contentAscii.Contains(s, StringComparison.OrdinalIgnoreCase))
                : rule.StringPatterns.Any(s => contentAscii.Contains(s, StringComparison.OrdinalIgnoreCase));
        }

        if (rule.RequiresAllPatterns && !stringMatches) return false;

        return byteMatches && stringMatches;
    }

    private static int IndexOfSequence(byte[] buffer, byte[] pattern)
    {
        if (pattern.Length == 0 || buffer.Length < pattern.Length) return -1;

        for (int i = 0; i <= buffer.Length - pattern.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (buffer[i + j] != pattern[j])
                {
                    match = false;
                    break;
                }
            }
            if (match) return i;
        }
        return -1;
    }

    private async Task<EngineScanResult?> ScanWithYaraCliAsync(string filePath, CancellationToken cancellationToken)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = _yaraBinaryPath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            // Arguments sécurisés
            startInfo.ArgumentList.Add("-m"); // Print metadata
            startInfo.ArgumentList.Add("-s"); // Print matching strings
            startInfo.ArgumentList.Add(filePath);

            using var process = new Process { StartInfo = startInfo };
            process.Start();

            string stdout = await process.StandardOutput.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);

            if (process.ExitCode == 0 && !string.IsNullOrWhiteSpace(stdout))
            {
                return EngineScanResult.Success(
                    EngineType.YARA,
                    ThreatVerdict.Malicious,
                    RiskLevel.High,
                    "YARA.Match.CLI",
                    stdout.Trim(),
                    0);
            }
        }
        catch
        {
            // Repli sur le moteur managé
        }

        return null;
    }

    private void RegisterBuiltinRules()
    {
        // 1. Règle EICAR Standard Antivirus Test
        _rules.Add(new YaraRuleDefinition
        {
            Name = "EICAR_Standard_Test_File",
            Description = "Signature de test antivirus standardisée EICAR",
            Severity = RiskLevel.Critical,
            ThreatType = "TestSign",
            StringPatterns = { "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" },
            RequiresAllPatterns = true
        });

        // 2. Règle Ransomware Generic Note
        _rules.Add(new YaraRuleDefinition
        {
            Name = "Ransomware_Payment_Note",
            Description = "Détection de chaînes caractéristiques de notes de rançon",
            Severity = RiskLevel.High,
            ThreatType = "Ransomware",
            StringPatterns = { "your files have been encrypted", "pay the ransom to recover your files" },
            RequiresAllPatterns = false
        });

        // 3. Règle Injection Processus Critique (Combinaison d'APIs PE)
        _rules.Add(new YaraRuleDefinition
        {
            Name = "Process_Injection_Heuristic",
            Description = "Présence suspecte de chaînes d'injection de mémoire dans d'autres processus",
            Severity = RiskLevel.High,
            ThreatType = "ProcessInjection",
            StringPatterns = { "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread" },
            RequiresAllPatterns = true // Exige la combinaison des 3 APIs pour éviter les faux positifs !
        });

        // 4. Règle Mimikatz / LSASS Dumping
        _rules.Add(new YaraRuleDefinition
        {
            Name = "Mimikatz_Lsass_Dump_Keywords",
            Description = "Détection de signatures d'extraction de mots de passe en mémoire",
            Severity = RiskLevel.Critical,
            ThreatType = "CredentialDumping",
            StringPatterns = { "sekurlsa::logonpasswords", "lsass.exe", "wdigest.dll" },
            RequiresAllPatterns = true
        });

        // 5. Règle Webshell PHP / Script malveillant
        _rules.Add(new YaraRuleDefinition
        {
            Name = "Webshell_Obfuscated_Eval",
            Description = "Exécution de code arbitraire obfusqué dans un script",
            Severity = RiskLevel.High,
            ThreatType = "Webshell",
            StringPatterns = { "eval(base64_decode(", "passthru($_POST" },
            RequiresAllPatterns = false
        });
    }

    private static List<YaraRuleDefinition> ParseYaraRuleContent(string content)
    {
        var rules = new List<YaraRuleDefinition>();
        // Protection ReDoS : timeout strict de 500 ms sur l'analyse regex des règles
        var ruleRegex = new Regex(@"rule\s+([A-Za-z0-9_]+)\s*\{([^}]+)\}", RegexOptions.Multiline, TimeSpan.FromMilliseconds(500));
        var matches = ruleRegex.Matches(content);

        foreach (Match match in matches)
        {
            string ruleName = match.Groups[1].Value;
            string body = match.Groups[2].Value;

            var stringRegex = new Regex(@"\$[A-Za-z0-9_]+\s*=\s*""([^""]+)""", RegexOptions.Multiline, TimeSpan.FromMilliseconds(500));
            var stringMatches = stringRegex.Matches(body);

            var stringPatterns = new List<string>();
            foreach (Match sMatch in stringMatches)
            {
                stringPatterns.Add(sMatch.Groups[1].Value);
            }

            if (stringPatterns.Count > 0)
            {
                rules.Add(new YaraRuleDefinition
                {
                    Name = ruleName,
                    Description = $"Règle YARA externe : {ruleName}",
                    Severity = RiskLevel.Medium,
                    ThreatType = "ExternalRule",
                    StringPatterns = stringPatterns,
                    RequiresAllPatterns = false
                });
            }
        }

        return rules;
    }

    private static string ResolveYaraBinary(string? customPath)
    {
        if (!string.IsNullOrEmpty(customPath) && File.Exists(customPath))
        {
            return customPath;
        }

        string[] candidates = {
            @"C:\Program Files\YARA\yara64.exe",
            @"C:\Program Files (x86)\YARA\yara64.exe",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"CyberSentinel\Yara\yara64.exe")
        };

        return candidates.FirstOrDefault(File.Exists) ?? string.Empty;
    }
}

