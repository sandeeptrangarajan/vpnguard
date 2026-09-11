namespace IPsecSecurityAnalyzer.Interfaces;

/// <summary>
/// Service interface for abstracting native desktop file pickers and dialogs.
/// </summary>
public interface IFileDialogService
{
    /// <summary>
    /// Displays a native Windows file open dialog for PCAP/PCAPNG packet capture files.
    /// </summary>
    /// <returns>Selected file path, or null if cancelled.</returns>
    string? OpenPcapFileDialog();

    /// <summary>
    /// Displays a native file open dialog for locating executable binaries (e.g. tshark.exe, python.exe).
    /// </summary>
    /// <returns>Selected file path, or null if cancelled.</returns>
    string? OpenExecutableFileDialog(string title = "Select Executable");

    /// <summary>
    /// Displays a native Windows save file dialog for exporting reports.
    /// </summary>
    /// <param name="defaultFileName">Default suggested file name.</param>
    /// <param name="filter">Filter string (e.g. PDF Files (*.pdf)|*.pdf).</param>
    /// <returns>Chosen destination file path, or null if cancelled.</returns>
    string? SaveFileDialog(string defaultFileName, string filter);
}
