using CyberSentinel.Application.DTOs;

namespace CyberSentinel.Application.Common.Interfaces;

public interface IPdfGenerator
{
    void GeneratePdf(SecurityReportDto report, Stream outputStream);
}

