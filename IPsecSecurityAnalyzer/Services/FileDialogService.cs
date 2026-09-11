using Microsoft.Win32;
using IPsecSecurityAnalyzer.Interfaces;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Concrete desktop file dialog provider using Windows Presentation Foundation common dialogs.
/// </summary>
public class FileDialogService : IFileDialogService
{
    public string? OpenPcapFileDialog()
    {
        var openFileDialog = new OpenFileDialog
        {
            Title = "Select IPsec / VPN Capture File",
            Filter = "Capture Files (*.pcap;*.pcapng)|*.pcap;*.pcapng|Wireshark / tcpdump PCAP (*.pcap)|*.pcap|Next Generation PCAP (*.pcapng)|*.pcapng|All Files (*.*)|*.*",
            FilterIndex = 1,
            Multiselect = false,
            CheckFileExists = true,
            CheckPathExists = true
        };

        bool? result = openFileDialog.ShowDialog();
        return result == true ? openFileDialog.FileName : null;
    }

    public string? OpenExecutableFileDialog(string title = "Select Executable")
    {
        var openFileDialog = new OpenFileDialog
        {
            Title = title,
            Filter = "Executable Files (*.exe)|*.exe|All Files (*.*)|*.*",
            FilterIndex = 1,
            Multiselect = false,
            CheckFileExists = true,
            CheckPathExists = true
        };

        bool? result = openFileDialog.ShowDialog();
        return result == true ? openFileDialog.FileName : null;
    }

    public string? SaveFileDialog(string defaultFileName, string filter)
    {
        var saveFileDialog = new SaveFileDialog
        {
            Title = "Export Report",
            FileName = defaultFileName,
            Filter = filter,
            FilterIndex = 1,
            CheckPathExists = true
        };

        bool? result = saveFileDialog.ShowDialog();
        return result == true ? saveFileDialog.FileName : null;
    }
}
