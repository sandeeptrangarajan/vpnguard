namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Represents metadata for a selected PCAP / PCAPNG packet capture file.
/// </summary>
public class PcapFileInfo
{
    public string FileName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public long FileSize { get; set; }
    public string FileExtension { get; set; } = string.Empty;
    public DateTime CreatedDate { get; set; }
    public DateTime LastModifiedDate { get; set; }

    /// <summary>
    /// Formatted file size string (e.g. "14.2 MB").
    /// </summary>
    public string FormattedFileSize
    {
        get
        {
            if (FileSize < 1024) return $"{FileSize} B";
            if (FileSize < 1024 * 1024) return $"{FileSize / 1024.0:F2} KB";
            if (FileSize < 1024 * 1024 * 1024) return $"{FileSize / (1024.0 * 1024.0):F2} MB";
            return $"{FileSize / (1024.0 * 1024.0 * 1024.0):F2} GB";
        }
    }
}
