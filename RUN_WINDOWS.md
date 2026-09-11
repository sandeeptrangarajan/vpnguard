# VPNGuard / IPsec Security Analyzer - Windows Run Guide

## Prerequisites

- .NET 8 SDK or later (the application targets `net8.0-windows`).
- Wireshark/TShark installed. The application can use `C:\Program Files\Wireshark\tshark.exe` or the path configured in Settings.
- Python 3 with the packages in `ai_engine/requirements.txt`.

Example Python packages:

```powershell
python -m pip install -r .\ai_engine\requirements.txt
```

## Run from source

From the repository root:

```powershell
& "C:\Program Files\dotnet\dotnet.exe" run --project ".\IPsecSecurityAnalyzer\IPsecSecurityAnalyzer.csproj"
```

If `dotnet` is on PATH, this is enough:

```powershell
dotnet run --project ".\IPsecSecurityAnalyzer\IPsecSecurityAnalyzer.csproj"
```

## Settings

Set **TShark Executable Path** to:

```text
C:\Program Files\Wireshark\tshark.exe
```

Set **Python Environment Path** to the actual Python executable, for example:

```text
C:\Users\<user>\AppData\Local\Python\pythoncore-3.14-64\python.exe
```

The application also auto-detects Python if the setting is empty.

## End-to-end workflow

1. Open **PCAP Analysis**.
2. Select a `.pcap` or `.pcapng` file.
3. Click **Analyze**.
4. The orchestrator runs TShark, packet parsing, IPsec/IKE/ESP analysis, security assessment, AI inference, and SQLite persistence once.
5. Dashboard, AI, Findings, Recommendations, History, and Reports use the same completed analysis snapshot.

The bundled `ai_engine` is copied into the application's build/publish output so `python -m ai_engine.infer` does not depend on a developer-specific working directory.
