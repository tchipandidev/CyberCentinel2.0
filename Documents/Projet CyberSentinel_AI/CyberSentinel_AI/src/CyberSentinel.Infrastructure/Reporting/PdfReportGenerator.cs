using System.Text;
using CyberSentinel.Application.Common.Interfaces;
using CyberSentinel.Application.DTOs;

namespace CyberSentinel.Infrastructure.Reporting;

/// <summary>
/// Générateur de rapports PDF natif conforme à la spécification PDF 1.4 (ISO 32000-1).
/// Produit des documents de synthèse exécutifs et techniques sans aucune dépendance tierce.
/// </summary>
public class PdfReportGenerator : IPdfGenerator
{
    public void GeneratePdf(SecurityReportDto report, Stream outputStream)
    {
        var builder = new PdfDocumentBuilder();

        // 1. En-tête officiel CyberSentinel AI
        builder.AddRectangle(30, 770, 535, 50, 0.05f, 0.1f, 0.18f); // Fond bleu nuit EDR
        builder.AddText("CYBERSENTINEL AI - RAPPORT D'AUDIT DE SÉCURITÉ", 45, 800, 15, isBold: true, r: 0f, g: 0.82f, b: 1f);
        builder.AddText($"Machine : {Sanitize(report.MachineName)} | OS : {Sanitize(report.OperatingSystem)} | Date : {report.FormattedDate}", 45, 782, 9, isBold: false, r: 0.8f, g: 0.85f, b: 0.9f);

        // 2. Synthèse Exécutive & Score de Posture
        builder.AddRectangle(30, 690, 535, 70, 0.09f, 0.11f, 0.14f); // Carte sombre
        builder.AddText("SYNTHESE DE POSTURE GLOBALE", 45, 742, 11, isBold: true, r: 0.94f, g: 0.96f, b: 0.98f);
        
        // Couleur du verdict de posture
        float vR = report.PostureScore >= 85 ? 0.25f : (report.PostureScore >= 60 ? 0.82f : 0.97f);
        float vG = report.PostureScore >= 85 ? 0.72f : (report.PostureScore >= 60 ? 0.60f : 0.32f);
        float vB = report.PostureScore >= 85 ? 0.31f : (report.PostureScore >= 60 ? 0.13f : 0.28f);

        builder.AddText($"Score de Posture : {report.PostureScore:F1} / 100 ({Sanitize(report.PostureVerdict)})", 45, 725, 12, isBold: true, vR, vG, vB);
        builder.AddText(Sanitize(report.ExecutiveSummary), 45, 705, 9.5f, isBold: false, r: 0.7f, g: 0.75f, b: 0.8f);

        // 3. Cartes d'Indicateurs Clés (KPI Grid)
        int yKpi = 620;
        int cardW = 100;
        int cardH = 55;

        // Fichiers analysés
        builder.AddRectangle(30, yKpi, cardW, cardH, 0.13f, 0.15f, 0.18f);
        builder.AddText("FICHIERS ANALYSES", 36, yKpi + 40, 7.5f, true, 0.6f, 0.65f, 0.7f);
        builder.AddText(report.FilesScanned.ToString(), 36, yKpi + 16, 18, true, 0.94f, 0.96f, 0.98f);

        // Menaces Détectées
        builder.AddRectangle(138, yKpi, cardW, cardH, 0.13f, 0.15f, 0.18f);
        builder.AddText("MENACES MALVEILLANTES", 144, yKpi + 40, 7.5f, true, 0.97f, 0.32f, 0.28f);
        builder.AddText(report.MaliciousFiles.ToString(), 144, yKpi + 16, 18, true, 0.97f, 0.32f, 0.28f);

        // Fichiers Suspects
        builder.AddRectangle(246, yKpi, cardW, cardH, 0.13f, 0.15f, 0.18f);
        builder.AddText("FICHIERS SUSPECTS", 252, yKpi + 40, 7.5f, true, 0.82f, 0.60f, 0.13f);
        builder.AddText(report.SuspiciousFiles.ToString(), 252, yKpi + 16, 18, true, 0.82f, 0.60f, 0.13f);

        // Vulnérabilités Critiques
        builder.AddRectangle(354, yKpi, cardW, cardH, 0.13f, 0.15f, 0.18f);
        builder.AddText("VULNERABILITES CVE CRIT.", 360, yKpi + 40, 7.5f, true, 0.97f, 0.32f, 0.28f);
        builder.AddText(report.CriticalVulnerabilities.ToString(), 360, yKpi + 16, 18, true, 0.97f, 0.32f, 0.28f);

        // Mises à jour en attente
        builder.AddRectangle(462, yKpi, cardW, cardH, 0.13f, 0.15f, 0.18f);
        builder.AddText("MISES A JOUR REQUISES", 468, yKpi + 40, 7.5f, true, 0f, 0.82f, 1f);
        builder.AddText(report.AvailableUpdates.ToString(), 468, yKpi + 16, 18, true, 0f, 0.82f, 1f);

        // 4. Section : Menaces et détections malveillantes
        int yPos = 585;
        builder.AddText("1. MENACES MALVEILLANTES & ALERTES ANOMALIES", 30, yPos, 11, true, 0.97f, 0.32f, 0.28f);
        yPos -= 16;

        if (report.DetectedThreats.Count == 0)
        {
            builder.AddText("Aucune menace active détectée sur les répertoires analysés. Signature ClamAV, règles YARA et IA conformes.", 35, yPos, 9, false, 0.25f, 0.72f, 0.31f);
            yPos -= 22;
        }
        else
        {
            foreach (var threat in report.DetectedThreats.Take(4))
            {
                string line = $"• [{threat.Verdict}] {Sanitize(threat.FileName)} - Détecté par: {Sanitize(threat.DetectionSummary)} (Hash: {threat.Sha256Hash[..Math.Min(16, threat.Sha256Hash.Length)]}...)";
                builder.AddText(line, 35, yPos, 8.5f, false, 0.95f, 0.95f, 0.95f);
                yPos -= 14;
            }
            yPos -= 8;
        }

        // 5. Section : Vulnérabilités CVE et sévérité CVSS
        builder.AddText("2. VULNERABILITES LOGICIELLES (NIST NVD / CVSS 3.1)", 30, yPos, 11, true, 0.82f, 0.60f, 0.13f);
        yPos -= 16;

        if (report.TopVulnerabilities.Count == 0)
        {
            builder.AddText("Aucune vulnérabilité critique identifiée sur l'inventaire logiciel actuel.", 35, yPos, 9, false, 0.25f, 0.72f, 0.31f);
            yPos -= 22;
        }
        else
        {
            foreach (var vuln in report.TopVulnerabilities.Take(5))
            {
                string vLine = $"• {vuln.CveId} | Score: {vuln.CvssScore:F1} ({vuln.SeverityBadge}) | App: {Sanitize(vuln.AffectedSoftware)} ({vuln.InstalledVersion}) | Correctif: {Sanitize(vuln.PatchedVersion ?? "Non publié")}";
                builder.AddText(vLine, 35, yPos, 8.5f, false, 0.95f, 0.95f, 0.95f);
                yPos -= 14;
            }
            yPos -= 8;
        }

        // 6. Section : Recommandations Tactiques et Stratégiques
        builder.AddText("3. PLAN D'ACTION & RECOMMANDATIONS DE REMEDIATION", 30, yPos, 11, true, 0f, 0.82f, 1f);
        yPos -= 16;

        foreach (var rec in report.StrategicRecommendations.Take(6))
        {
            builder.AddText($"✔ {Sanitize(rec)}", 35, yPos, 9, false, 0.85f, 0.9f, 0.95f);
            yPos -= 15;
        }

        // 7. Pied de page sécurisé
        builder.AddRectangle(30, 25, 535, 1, 0.25f, 0.28f, 0.32f);
        builder.AddText("CyberSentinel AI Endpoint Protection & Vulnerability Management - Document confidentiel généré automatiquement", 30, 14, 8, false, 0.5f, 0.55f, 0.6f);

        // Écriture du document PDF complet
        byte[] pdfBytes = builder.BuildPdfBytes();
        outputStream.Write(pdfBytes, 0, pdfBytes.Length);
    }

    private static string Sanitize(string input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        // Supprimer caractères accentués non standard pour police Type1 Helvetica basique
        return input
            .Replace("é", "e").Replace("è", "e").Replace("ê", "e").Replace("ë", "e")
            .Replace("à", "a").Replace("â", "a").Replace("ä", "a")
            .Replace("î", "i").Replace("ï", "i")
            .Replace("ô", "o").Replace("ö", "o")
            .Replace("ù", "u").Replace("û", "u").Replace("ü", "u")
            .Replace("ç", "c").Replace("É", "E").Replace("È", "E")
            .Replace("À", "A").Replace("Ç", "C")
            .Replace("•", "-").Replace("✔", "[OK]")
            .Replace("⚠️", "[!]")
            .Replace("(", "[").Replace(")", "]");
    }

    private class PdfDocumentBuilder
    {
        private readonly StringBuilder _content = new();

        public void AddRectangle(float x, float y, float width, float height, float r, float g, float b)
        {
            _content.AppendLine($"{r:F3} {g:F3} {b:F3} rg");
            _content.AppendLine($"{x:F2} {y:F2} {width:F2} {height:F2} re");
            _content.AppendLine("f");
        }

        public void AddText(string text, float x, float y, float fontSize, bool isBold = false, float r = 0f, float g = 0f, float b = 0f)
        {
            string fontName = isBold ? "/F2" : "/F1";
            string safeText = text.Replace("\\", "\\\\").Replace("(", "\\(").Replace(")", "\\)");

            _content.AppendLine("BT");
            _content.AppendLine($"{fontName} {fontSize:F1} Tf");
            _content.AppendLine($"{r:F3} {g:F3} {b:F3} rg");
            _content.AppendLine($"{x:F2} {y:F2} Td");
            _content.AppendLine($"({safeText}) Tj");
            _content.AppendLine("ET");
        }

        public byte[] BuildPdfBytes()
        {
            byte[] streamBytes = Encoding.Latin1.GetBytes(_content.ToString());

            var sb = new StringBuilder();
            sb.Append("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

            var offsets = new List<long>();

            // Obj 1 : Catalog
            offsets.Add(sb.Length);
            sb.Append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

            // Obj 2 : Pages
            offsets.Add(sb.Length);
            sb.Append("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

            // Obj 3 : Page (A4 : 595 x 842 pt)
            offsets.Add(sb.Length);
            sb.Append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>\nendobj\n");

            // Obj 4 : Stream
            offsets.Add(sb.Length);
            sb.Append($"4 0 obj\n<< /Length {streamBytes.Length} >>\nstream\n");
            byte[] preStreamBytes = Encoding.Latin1.GetBytes(sb.ToString());

            sb.Clear();
            sb.Append("\nendstream\nendobj\n");

            // Obj 5 : Font F1 (Helvetica)
            long font1Offset = preStreamBytes.Length + streamBytes.Length + Encoding.Latin1.GetByteCount(sb.ToString());
            sb.Append("5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n");

            // Obj 6 : Font F2 (Helvetica-Bold)
            long font2Offset = preStreamBytes.Length + streamBytes.Length + Encoding.Latin1.GetByteCount(sb.ToString());
            sb.Append("6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n");

            byte[] postStreamBytes = Encoding.Latin1.GetBytes(sb.ToString());

            // Recalcul des offsets précis
            long currentOffset = 0;
            var finalOffsets = new List<long>();

            string header = "%PDF-1.4\n%\xE2\xE3\xCF\xD3\n";
            currentOffset += Encoding.Latin1.GetByteCount(header);

            finalOffsets.Add(currentOffset);
            string obj1 = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";
            currentOffset += Encoding.Latin1.GetByteCount(obj1);

            finalOffsets.Add(currentOffset);
            string obj2 = "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n";
            currentOffset += Encoding.Latin1.GetByteCount(obj2);

            finalOffsets.Add(currentOffset);
            string obj3 = "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>\nendobj\n";
            currentOffset += Encoding.Latin1.GetByteCount(obj3);

            finalOffsets.Add(currentOffset);
            string obj4Head = $"4 0 obj\n<< /Length {streamBytes.Length} >>\nstream\n";
            currentOffset += Encoding.Latin1.GetByteCount(obj4Head);
            currentOffset += streamBytes.Length;
            string obj4End = "\nendstream\nendobj\n";
            currentOffset += Encoding.Latin1.GetByteCount(obj4End);

            finalOffsets.Add(currentOffset);
            string obj5 = "5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n";
            currentOffset += Encoding.Latin1.GetByteCount(obj5);

            finalOffsets.Add(currentOffset);
            string obj6 = "6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n";
            currentOffset += Encoding.Latin1.GetByteCount(obj6);

            long xrefOffset = currentOffset;

            var xrefSb = new StringBuilder();
            xrefSb.Append("xref\n0 7\n");
            xrefSb.Append("0000000000 65535 f \n");
            foreach (var off in finalOffsets)
            {
                xrefSb.Append($"{off:D10} 00000 n \n");
            }
            xrefSb.Append($"trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n{xrefOffset}\n%%EOF\n");

            byte[] xrefBytes = Encoding.Latin1.GetBytes(xrefSb.ToString());

            // Assemblage final du buffer
            using var ms = new MemoryStream();
            byte[] hBytes = Encoding.Latin1.GetBytes(header);
            ms.Write(hBytes, 0, hBytes.Length);
            byte[] o1Bytes = Encoding.Latin1.GetBytes(obj1);
            ms.Write(o1Bytes, 0, o1Bytes.Length);
            byte[] o2Bytes = Encoding.Latin1.GetBytes(obj2);
            ms.Write(o2Bytes, 0, o2Bytes.Length);
            byte[] o3Bytes = Encoding.Latin1.GetBytes(obj3);
            ms.Write(o3Bytes, 0, o3Bytes.Length);
            byte[] o4hBytes = Encoding.Latin1.GetBytes(obj4Head);
            ms.Write(o4hBytes, 0, o4hBytes.Length);
            ms.Write(streamBytes, 0, streamBytes.Length);
            byte[] o4eBytes = Encoding.Latin1.GetBytes(obj4End);
            ms.Write(o4eBytes, 0, o4eBytes.Length);
            byte[] o5Bytes = Encoding.Latin1.GetBytes(obj5);
            ms.Write(o5Bytes, 0, o5Bytes.Length);
            byte[] o6Bytes = Encoding.Latin1.GetBytes(obj6);
            ms.Write(o6Bytes, 0, o6Bytes.Length);
            ms.Write(xrefBytes, 0, xrefBytes.Length);

            return ms.ToArray();
        }
    }
}
