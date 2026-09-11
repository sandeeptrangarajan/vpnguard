using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Production report generation engine for Phase 6.
/// Generates professional cybersecurity assessment PDF reports and formatted JSON audit files.
/// Implements standard PostScript/PDF generation without heavy unmanaged dependencies.
/// </summary>
public class ReportService : IReportService
{
    private readonly IPcapAnalyzer? _pcapAnalyzer;
    private readonly IIpsecAnalyzer? _ipsecAnalyzer;
    private readonly ISecurityAssessmentService? _assessmentService;
    private readonly IAiAnalysisService? _aiAnalysisService;
    private readonly IAnalysisOrchestrator? _orchestrator;
    private readonly List<string> _generatedReports = new();

    private static readonly JsonSerializerOptions _jsonExportOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    public ReportService(
        IPcapAnalyzer? pcapAnalyzer = null,
        IIpsecAnalyzer? ipsecAnalyzer = null,
        ISecurityAssessmentService? assessmentService = null,
        IAiAnalysisService? aiAnalysisService = null,
        IAnalysisOrchestrator? orchestrator = null)
    {
        _pcapAnalyzer = pcapAnalyzer;
        _ipsecAnalyzer = ipsecAnalyzer;
        _assessmentService = assessmentService;
        _aiAnalysisService = aiAnalysisService;
        _orchestrator = orchestrator;
    }

    public async Task<string> GeneratePdfReportAsync(AnalysisReportData reportData, string destinationPath)
    {
        if (reportData == null)
            throw new ArgumentNullException(nameof(reportData));

        return await Task.Run(() =>
        {
            try
            {
                var directory = Path.GetDirectoryName(destinationPath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var pdfBytes = BuildPdfDocument(reportData);
                File.WriteAllBytes(destinationPath, pdfBytes);

                lock (_generatedReports)
                {
                    if (!_generatedReports.Contains(destinationPath))
                    {
                        _generatedReports.Add(destinationPath);
                    }
                }

                return destinationPath;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ReportService] PDF generation failed: {ex.Message}");
                throw;
            }
        });
    }

    public async Task<string> GeneratePdfReportAsync(string destinationPath)
    {
        // Prefer the single completed snapshot produced by AnalysisOrchestrator.
        // This prevents report generation from rerunning AI/IPsec analysis.
        var currentData = _orchestrator?.LastReportData ?? await AssembleActiveReportDataAsync();
        return await GeneratePdfReportAsync(currentData, destinationPath);
    }

    public async Task<string> ExportJsonAsync(AnalysisReportData reportData, string destinationPath)
    {
        if (reportData == null)
            throw new ArgumentNullException(nameof(reportData));

        return await Task.Run(() =>
        {
            try
            {
                var directory = Path.GetDirectoryName(destinationPath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var jsonString = JsonSerializer.Serialize(reportData, _jsonExportOptions);
                File.WriteAllText(destinationPath, jsonString, Encoding.UTF8);

                lock (_generatedReports)
                {
                    if (!_generatedReports.Contains(destinationPath))
                    {
                        _generatedReports.Add(destinationPath);
                    }
                }

                return destinationPath;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ReportService] JSON export failed: {ex.Message}");
                throw;
            }
        });
    }

    public Task<IReadOnlyList<string>> GetGeneratedReportsAsync()
    {
        lock (_generatedReports)
        {
            return Task.FromResult<IReadOnlyList<string>>(_generatedReports.ToList());
        }
    }

    private async Task<AnalysisReportData> AssembleActiveReportDataAsync()
    {
        var data = new AnalysisReportData();

        if (_pcapAnalyzer != null && _pcapAnalyzer.LastAnalysisResult != null)
        {
            var pcap = _pcapAnalyzer.LastAnalysisResult;
            data.FileName = pcap.FileName;
            data.FilePath = pcap.FilePath;
            data.FileSizeBytes = pcap.FileSize;
            data.CaptureDurationSeconds = pcap.Duration.TotalSeconds;
            data.TotalPackets = pcap.PacketCount;
            data.TotalBytes = pcap.TotalBytes;
            data.IpsecDetected = pcap.IpsecPacketCount > 0;
            data.IpsecPacketCount = pcap.IpsecPacketCount;
            data.IkePacketCount = pcap.IkePacketCount;
            data.EspPacketCount = pcap.EspPacketCount;
            data.AhPacketCount = pcap.AhPacketCount;
            data.TcpPacketCount = pcap.TcpPacketCount;
            data.UdpPacketCount = pcap.UdpPacketCount;
            data.IcmpPacketCount = pcap.Protocols.FirstOrDefault(p => p.ProtocolName.Equals("ICMP", StringComparison.OrdinalIgnoreCase))?.PacketCount ?? 0;
            data.ProtocolDistribution = pcap.Protocols.ToList();
        }

        if (_ipsecAnalyzer != null)
        {
            var ipsec = await _ipsecAnalyzer.GetIpsecAnalysisAsync();
            if (ipsec != null && ipsec.IsAnalyzed)
            {
                data.HasIpsecAnalysis = true;
                data.IkeVersion = ipsec.IkevVersion;
                data.ExchangeType = ipsec.ExchangeType;
                data.AuthenticationMethod = ipsec.AuthenticationMethod;
                data.EncryptionAlgorithm = ipsec.EncryptionAlgorithm;
                data.IntegrityAlgorithm = ipsec.IntegrityAlgorithm;
                data.DhGroup = ipsec.DhGroup;
                data.PfsEnabled = ipsec.PfsEnabled;
                data.ReplayProtectionEnabled = ipsec.ReplayProtectionEnabled;
                data.IpsecMode = ipsec.IpsecMode;
                data.Spi = ipsec.Spi;
                data.KeyLifetime = ipsec.KeyLifetime;
                data.SaProposals = ipsec.SaProposals.ToList();
                data.Handshakes = ipsec.Handshakes.ToList();
                data.EspSessions = ipsec.EspSessions.ToList();
            }
        }

        if (_assessmentService != null)
        {
            var assessment = await _assessmentService.GetSecurityAssessmentAsync();
            if (assessment != null && assessment.HasAssessment)
            {
                data.HasSecurityAssessment = true;
                data.OverallRiskScore = assessment.OverallRiskScore;
                data.RiskLevel = assessment.RiskLevel;
                data.AssessmentCoverage = assessment.AssessmentCoverage;
                data.AssessedParameterCount = assessment.AssessedParameterCount;
                data.UnknownParameterCount = assessment.UnknownParameterCount;
                data.AssessmentSummary = assessment.Summary;
                data.CriticalFindingCount = assessment.CriticalCount;
                data.HighFindingCount = assessment.HighCount;
                data.MediumFindingCount = assessment.MediumCount;
                data.LowFindingCount = assessment.LowCount;
                data.InformationalFindingCount = assessment.InformationalCount;
                data.Findings = assessment.Findings.ToList();
                data.Recommendations = assessment.Recommendations.ToList();
            }
        }

        return data;
    }

    /// <summary>
    /// Builds an official, standard-compliant PDF document conforming to ISO 32000-1 (PDF 1.4).
    /// Generates structured professional cybersecurity reports with executive summaries, scope,
    /// traffic statistics, IPsec dissection, vulnerability findings, recommendations, and AI inference.
    /// </summary>
    private static byte[] BuildPdfDocument(AnalysisReportData report)
    {
        var lines = new List<string>();

        // Header / Banner
        lines.Add("VPNGuard - IPsec VPN Security Assessment Report");
        lines.Add("Automated Protocol Audit & Compliance Analysis (SIH26160)");
        lines.Add(new string('=', 78));
        lines.Add($"Analysis ID:       {report.AnalysisId}");
        lines.Add($"Generated Date:    {report.FormattedTimestamp}");
        lines.Add($"Target PCAP File:  {report.FileName} ({report.FormattedFileSize})");
        lines.Add($"Engine Version:    {report.ApplicationVersion}");
        lines.Add(string.Empty);

        // Section 1: Executive Summary
        lines.Add("1. EXECUTIVE SUMMARY");
        lines.Add(new string('-', 78));
        lines.Add($"Security Score:    {report.FormattedRiskScore} (Risk Level: {report.FormattedRiskLevel})");
        lines.Add($"Assessment Cover:  {report.FormattedCoverage} (Assessed: {report.AssessedParameterCount}, Unknown: {report.UnknownParameterCount})");
        lines.Add($"IPsec Observed:    {(report.IpsecDetected ? "YES - Active IPsec Traffic Identified" : "NO - No ESP/IKE Frames Observed")}");
        lines.Add($"Total Findings:    {report.Findings.Count} (Critical: {report.CriticalFindingCount}, High: {report.HighFindingCount}, Med: {report.MediumFindingCount}, Low: {report.LowFindingCount})");
        if (report.HasAiAnalysis)
        {
            lines.Add($"AI-Inferred Type:  {report.AiTrafficType ?? "Unknown"} (Confidence: {(report.AiConfidence.HasValue ? $"{report.AiConfidence.Value * 100:F1}%" : "N/A")})");
            lines.Add($"Anomaly Status:    {(report.AnomalyDetected ? "Potentially unusual traffic pattern" : "Normal traffic pattern")}");
        }
        else
        {
            lines.Add("AI-Inferred Type:  AI analysis not available for this assessment.");
        }
        lines.Add(string.Empty);

        // Section 2: Analysis Scope & Principles
        lines.Add("2. ANALYSIS SCOPE & METHODOLOGY");
        lines.Add(new string('-', 78));
        lines.Add("Data Classification Principles:");
        lines.Add("  - Observed: Directly dissected from cleartext IKE/IPsec packet headers.");
        lines.Add("  - Inferred: Machine-learning classifications derived from metadata features.");
        lines.Add("  - Unknown:  Parameters not captured during handshake negotiation.");
        lines.Add("IMPORTANT PRIVACY & SECURITY STATEMENT:");
        lines.Add("Encrypted IPsec ESP payload contents were NOT decrypted or inspected.");
        lines.Add("Traffic classification is based exclusively on observable metadata statistics.");
        lines.Add(string.Empty);

        // Section 3: Traffic Overview
        lines.Add("3. PCAP & TRAFFIC VOLUME OVERVIEW");
        lines.Add(new string('-', 78));
        lines.Add($"Total Packets:     {report.TotalPackets:N0}");
        lines.Add($"Total Volume:      {report.FormattedFileSize} ({report.TotalBytes:N0} bytes)");
        lines.Add($"Capture Duration:  {report.CaptureDurationSeconds:F2} seconds");
        lines.Add($"IPsec ESP Packets: {report.EspPacketCount:N0}");
        lines.Add($"IKE Handshakes:    {report.IkePacketCount:N0}");
        lines.Add($"AH Packets:        {report.AhPacketCount:N0}");
        lines.Add($"TCP Frames:        {report.TcpPacketCount:N0}");
        lines.Add($"UDP Frames:        {report.UdpPacketCount:N0}");
        lines.Add($"ICMP Packets:      {report.IcmpPacketCount:N0}");
        lines.Add(string.Empty);

        // Section 4: IPsec Dissection
        lines.Add("4. IPSEC & IKE PROTOCOL DISSECTION");
        lines.Add(new string('-', 78));
        if (report.HasIpsecAnalysis)
        {
            lines.Add($"IKE Protocol Ver:  {report.IkeVersion ?? "Unknown"}");
            lines.Add($"Exchange Type:     {report.ExchangeType ?? "Unknown"}");
            lines.Add($"Auth Method:       {report.AuthenticationMethod ?? "Not negotiated / Not clear"}");
            lines.Add($"Cipher Suite:      {report.EncryptionAlgorithm ?? "Not observed in clear"}");
            lines.Add($"Integrity Hash:    {report.IntegrityAlgorithm ?? "Not observed in clear"}");
            lines.Add($"Diffie-Hellman:    {report.DhGroup ?? "Not observed in clear"}");
            lines.Add($"Forward Secrecy:   {(report.PfsEnabled.HasValue ? (report.PfsEnabled.Value ? "Enabled (Verified)" : "Disabled / Not Observed") : "Unknown")}");
            lines.Add($"Replay Protection: {(report.ReplayProtectionEnabled.HasValue ? (report.ReplayProtectionEnabled.Value ? "Enabled (Active Sequence Tracking)" : "Disabled / Gaps") : "Unknown")}");
            lines.Add($"Operating Mode:    {report.IpsecMode ?? "Unknown"}");
            lines.Add($"SPI / Key Life:    {report.Spi ?? "Unknown"} / {report.KeyLifetime ?? "Default"}");
        }
        else
        {
            lines.Add("IPsec protocol parameters could not be dissected from this capture.");
        }
        lines.Add(string.Empty);

        // Section 5: Security Findings
        lines.Add("5. SECURITY FINDINGS & VULNERABILITY AUDIT");
        lines.Add(new string('-', 78));
        if (report.Findings.Count > 0)
        {
            int idx = 1;
            foreach (var f in report.Findings)
            {
                lines.Add($"[{idx++}] {f.Severity.ToString().ToUpperInvariant()} - {f.Title}");
                lines.Add($"     Rule ID:        {f.RuleId} (Category: {f.Category})");
                lines.Add($"     Observed:       {f.ObservedValue}");
                lines.Add($"     Recommendation: {f.Recommendation}");
                if (!string.IsNullOrWhiteSpace(f.Evidence))
                {
                    lines.Add($"     Evidence:       {f.Evidence}");
                }
                lines.Add(string.Empty);
            }
        }
        else
        {
            lines.Add(report.HasSecurityAssessment
                ? "No security vulnerabilities or weak cryptographic proposals were identified."
                : "Security assessment was not performable on this capture.");
            lines.Add(string.Empty);
        }

        // Section 6: Recommendations
        lines.Add("6. PRIORITIZED REMEDIATION RECOMMENDATIONS");
        lines.Add(new string('-', 78));
        if (report.Recommendations.Count > 0)
        {
            int idx = 1;
            foreach (var r in report.Recommendations)
            {
                lines.Add($"[{idx++}] {r.Priority.ToString().ToUpperInvariant()} Priority: {r.Title}");
                lines.Add($"     Action:         {r.Recommendation}");
                lines.Add($"     Reason:         {r.Reason}");
                lines.Add(string.Empty);
            }
        }
        else
        {
            lines.Add("No active remediation recommendations required for the observed parameters.");
            lines.Add(string.Empty);
        }

        // Section 7: AI Analysis
        lines.Add("7. AI-BASED TRAFFIC CLASSIFICATION & ANOMALY DETECTION");
        lines.Add(new string('-', 78));
        if (report.HasAiAnalysis)
        {
            lines.Add($"AI-Inferred Traffic Type: {report.AiTrafficType ?? "Unknown"}");
            lines.Add($"Model Confidence:         {(report.AiConfidence.HasValue ? $"{report.AiConfidence.Value * 100:F2}%" : "N/A")}");
            lines.Add($"Behavioral Anomaly:       {(report.AnomalyDetected ? "Potentially unusual traffic pattern" : "Normal Profile")}");
            if (report.TopFeatures.Count > 0)
            {
                lines.Add("Top Contributing Features (Explainability):");
                foreach (var tf in report.TopFeatures)
                {
                    lines.Add($"  - {tf.Name}: {tf.Importance * 100:F2}% importance");
                }
            }
            if (!string.IsNullOrWhiteSpace(report.AiExplanation))
            {
                lines.Add(string.Empty);
                lines.Add($"Inference Explanation: {report.AiExplanation}");
            }
        }
        else
        {
            lines.Add("AI analysis was not available for this assessment.");
        }
        lines.Add(string.Empty);

        // Section 8: Assessment Limitations
        lines.Add("8. ASSESSMENT LIMITATIONS & ETHICAL NOTICE");
        lines.Add(new string('-', 78));
        lines.Add("1. Encrypted ESP payload content was not directly observed or decrypted.");
        lines.Add("2. Parameters exchanged prior to capture initiation cannot be passively confirmed.");
        lines.Add("3. AI traffic classification represents probabilistic statistical inference.");
        lines.Add("4. The VPNGuard risk score is an application-defined risk heuristic.");
        lines.Add(new string('=', 78));
        lines.Add("VPNGuard Defensive Security Framework - End of Report");

        return GenerateStandardPdf(lines);
    }

    /// <summary>
    /// Compiles a set of formatted text lines into a valid, standard-compliant PDF file.
    /// Uses Courier monospace typography with pagination, cross-reference table, and header/trailers.
    /// </summary>
    private static byte[] GenerateStandardPdf(IReadOnlyList<string> lines)
    {
        const int LinesPerPage = 54;
        var pageCount = (int)Math.Ceiling(lines.Count / (double)LinesPerPage);
        if (pageCount < 1) pageCount = 1;

        var pdf = new MemoryStream();
        var offsets = new List<long>();

        void Write(string s)
        {
            var b = Encoding.ASCII.GetBytes(s);
            pdf.Write(b, 0, b.Length);
        }

        // 1. PDF Header
        Write("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

        // Object 1: Catalog
        offsets.Add(pdf.Position);
        Write("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

        // Object 2: Pages tree
        offsets.Add(pdf.Position);
        var pageRefs = new StringBuilder();
        for (int p = 0; p < pageCount; p++)
        {
            pageRefs.Append($"{3 + p * 2} 0 R ");
        }
        Write($"2 0 obj\n<< /Type /Pages /Kids [ {pageRefs} ] /Count {pageCount} >>\nendobj\n");

        // Generate pages
        for (int p = 0; p < pageCount; p++)
        {
            var pageObjNum = 3 + p * 2;
            var contentObjNum = pageObjNum + 1;

            // Page Object
            offsets.Add(pdf.Position);
            Write($"{pageObjNum} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {contentObjNum} 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Courier >> >> >> >>\nendobj\n");

            // Content Stream Object
            offsets.Add(pdf.Position);
            var pageLines = lines.Skip(p * LinesPerPage).Take(LinesPerPage).ToList();

            var streamBuilder = new StringBuilder();
            streamBuilder.Append("BT\n/F1 9.5 Tf\n12 TL\n45 745 Td\n");

            for (int i = 0; i < pageLines.Count; i++)
            {
                var line = pageLines[i];
                var escaped = line.Replace("\\", "\\\\").Replace("(", "\\(").Replace(")", "\\)");
                streamBuilder.Append($"({escaped}) '\n");
            }

            // Add page numbering at bottom
            streamBuilder.Append($"ET\nBT\n/F1 8 Tf\n500 30 Td\n(Page {p + 1} of {pageCount}) Tj\nET\n");

            var streamBytes = Encoding.ASCII.GetBytes(streamBuilder.ToString());
            Write($"{contentObjNum} 0 obj\n<< /Length {streamBytes.Length} >>\nstream\n");
            pdf.Write(streamBytes, 0, streamBytes.Length);
            Write("\nendstream\nendobj\n");
        }

        // Cross-Reference Table
        var xrefOffset = pdf.Position;
        var totalObjects = 2 + pageCount * 2;
        Write($"xref\n0 {totalObjects + 1}\n0000000000 65535 f \n");
        for (int i = 0; i < offsets.Count; i++)
        {
            Write($"{offsets[i]:D10} 00000 n \n");
        }

        // Trailer
        Write($"trailer\n<< /Size {totalObjects + 1} /Root 1 0 R >>\nstartxref\n{xrefOffset}\n%%EOF\n");

        return pdf.ToArray();
    }
}
