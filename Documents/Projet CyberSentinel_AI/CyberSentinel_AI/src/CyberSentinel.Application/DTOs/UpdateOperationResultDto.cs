namespace CyberSentinel.Application.DTOs;

public class UpdateOperationResultDto
{
    public bool Success { get; set; }
    public string PackageId { get; set; } = string.Empty;
    public string ApplicationName { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public int ExitCode { get; set; }
    public string ConsoleOutput { get; set; } = string.Empty;
    public TimeSpan Duration { get; set; }
    public bool RequiredElevation { get; set; }
    public bool RequiresConfirmation { get; set; }
}

