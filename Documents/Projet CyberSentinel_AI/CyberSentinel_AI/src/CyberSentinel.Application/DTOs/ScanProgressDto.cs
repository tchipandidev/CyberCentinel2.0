namespace CyberSentinel.Application.DTOs;

public class ScanProgressDto
{
    public string CurrentFilePath { get; set; } = string.Empty;
    public string CurrentFileName { get; set; } = string.Empty;
    public int ProcessedFilesCount { get; set; }
    public int TotalFilesCount { get; set; }
    public int ThreatsFoundCount { get; set; }
    public double ProgressPercentage => TotalFilesCount > 0 
        ? Math.Min(100.0, Math.Round((double)ProcessedFilesCount / TotalFilesCount * 100, 1)) 
        : 0.0;
}

