namespace CyberSentinel.Domain.ValueObjects;

public record CpeIdentifier
{
    public string Part { get; init; } = "a"; // "a" for application, "o" for operating system
    public string Vendor { get; init; } = string.Empty;
    public string Product { get; init; } = string.Empty;
    public string Version { get; init; } = "*";
    public string Update { get; init; } = "*";

    public string ToCpe23Uri()
    {
        string safeVendor = Sanitize(Vendor);
        string safeProduct = Sanitize(Product);
        string safeVersion = string.IsNullOrWhiteSpace(Version) ? "*" : Sanitize(Version);
        return $"cpe:2.3:{Part}:{safeVendor}:{safeProduct}:{safeVersion}:*:*:*:*:*:*:*";
    }

    private static string Sanitize(string input)
    {
        return input.Trim().ToLowerInvariant()
            .Replace(" ", "_")
            .Replace("(", "")
            .Replace(")", "")
            .Replace("[", "")
            .Replace("]", "")
            .Replace("/", "_")
            .Replace("\\", "_");
    }
}

